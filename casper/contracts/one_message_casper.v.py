# Information about validators
validators: public({
    # Used to determine the amount of wei the validator holds. To get the actual
    # amount of wei, multiply this by the deposit_scale_factor.
    deposit: decimal (wei/m),
    # The dynasty the validator is joining
    dynasty_start: num,
    # The dynasty the validator is leaving
    dynasty_end: num,
    # The address which the validator's signatures must verify to (to be later replaced with validation code)
    addr: address,
    # Addess to withdraw to
    withdrawal_addr: address,
    # Previous epoch in which this validator voted
    prev_vote_epoch: num
}[num])

# Number of validators
nextValidatorIndex: public(num)

# The current dynasty (validator set changes between dynasties)
dynasty: public(num)

# Amount of wei added to the total deposits in the next dynasty
next_dynasty_wei_delta: public(decimal(wei / m))

# Amount of wei added to the total deposits in the dynasty after that
second_next_dynasty_wei_delta: public(decimal(wei / m))

# Total deposits in the current dynasty
total_curdyn_deposits: decimal(wei / m)

# Total deposits in the previous dynasty
total_prevdyn_deposits: decimal(wei / m)

# Mapping of dynasty to start epoch of that dynasty
dynasty_start_epoch: public(num[num])

# Mapping of epoch to what dynasty it is
dynasty_in_epoch: public(num[num])

# Information for use in processing cryptoeconomic commitments
consensus_messages: public({
    # How many votes are there for this hash from the current dynasty
    cur_dyn_votes: decimal(wei / m)[bytes32],
    # Bitmap of which validator IDs have already voted
    vote_bitmap: num256[num][bytes32],
    # From the previous dynasty
    prev_dyn_votes: decimal(wei / m)[bytes32],
    # Is a vote referencing the given checkpoint hash justified?
    checkpoint_hash_justified: bool[bytes32],
}[num]) # index: epoch

# Checkpoint hashes for each epoch
checkpoint_hashes: public(bytes32[num])

# Is the current expected hash justified
main_hash_justified: public(bool)

# Is the current expected hash finalized?
main_hash_finalized: public(bool)

# Value used to calculate the per-epoch fee that validators should be charged
deposit_scale_factor: public(decimal(m)[num])

# Length of an epoch in blocks
epoch_length: public(num)

# Withdrawal delay in blocks
withdrawal_delay: num

# Current epoch
current_epoch: public(num)

# Last finalized epoch
last_finalized_epoch: public(num)

# Last justified epoch
last_justified_epoch: public(num)

# Expected source epoch for a prepare
expected_source_epoch: public(num)

# Can withdraw destroyed deposits
owner: address

# Total deposits destroyed
total_destroyed: wei_value

# Sighash calculator library address
sighasher: address

# Purity checker library address
purity_checker: address

# Reward for vote, as fraction of deposit size
reward_factor: public(decimal)

# Base interest factor
base_interest_factor: public(decimal)

# Base penalty factor
base_penalty_factor: public(decimal)

# Current penalty factor
current_penalty_factor: public(decimal)

# Have I already been initialized?
initialized: bool

# Log topic for vote
vote_log_topic: bytes32

# Debugging
latest_nvf: public(decimal)
# latest_ncf: public(decimal)
latest_resize_factor: public(decimal)

# the epoch where the current epoch is referred is justified
# ex: epoch_justified_links[epoch][source] = True
epoch_justified_links: bool[num][num]

def initiate(# Epoch length, delay in epochs for withdrawing
             _epoch_length: num, _withdrawal_delay: num,
             # Owner (backdoor), sig hash calculator, purity checker
             _owner: address, _sighasher: address, _purity_checker: address,
             # Base interest and base penalty factors
             _base_interest_factor: decimal, _base_penalty_factor: decimal):
    assert not self.initialized
    self.initialized = True
    # Epoch length
    self.epoch_length = _epoch_length
    # Delay in epochs for withdrawing
    self.withdrawal_delay = _withdrawal_delay
    # Temporary backdoor for testing purposes (to allow recovering destroyed deposits)
    self.owner = _owner
    # Set deposit scale factor
    self.deposit_scale_factor[0] = 100.0
    # Start dynasty counter at 0
    self.dynasty = 0
    # Initialize the epoch counter
    self.current_epoch = block.number / self.epoch_length
    # Set the sighash calculator address
    self.sighasher = _sighasher
    # Set the purity checker address
    self.purity_checker = _purity_checker
    # Set initial total deposit counter
    self.total_curdyn_deposits = 0
    self.total_prevdyn_deposits = 0
    # Constants that affect interest rates and penalties
    self.base_interest_factor = _base_interest_factor
    self.base_penalty_factor = _base_penalty_factor
    # Log topics for vote
    self.vote_log_topic = sha3("vote()")

# Called at the start of any epoch
def initialize_epoch(epoch: num):
    # Check that the epoch actually has started
    computed_current_epoch = block.number / self.epoch_length
    assert epoch <= computed_current_epoch and epoch == self.current_epoch + 1
    # Compute square root factor
    ether_deposited_as_number = floor(max(self.total_prevdyn_deposits, self.total_curdyn_deposits) * 
                                      self.deposit_scale_factor[epoch - 1] / as_wei_value(1, ether)) + 1
    sqrt = ether_deposited_as_number / 2.0
    for i in range(20):
        sqrt = (sqrt + (ether_deposited_as_number / sqrt)) / 2
    # Compute log of epochs since last finalized
    log_dist = 0
    fac = epoch - self.last_finalized_epoch
    for i in range(20):
        if fac <= 1:
            break
        fac /= 2
        log_dist += 1
    # Base interest rate
    BIR = self.base_interest_factor / sqrt
    # Base penalty rate
    BP = BIR + self.base_penalty_factor * log_dist
    self.current_penalty_factor = BP
    # Calculate interest rate for this epoch
    if self.total_curdyn_deposits > 0 and self.total_prevdyn_deposits > 0:
        # Fraction that voted
        cur_vote_frac = self.consensus_messages[epoch - 1].cur_dyn_votes[self.checkpoint_hashes[epoch - 1]] / self.total_curdyn_deposits
        prev_vote_frac = self.consensus_messages[epoch - 1].prev_dyn_votes[self.checkpoint_hashes[epoch - 1]] / self.total_prevdyn_deposits
        non_vote_frac = 1 - min(cur_vote_frac, prev_vote_frac)
        # Compute "interest" - base interest minus penalties for not voting
        # If a validator votes, they pay this, but then get it back when rewarded
        # as part of the vote function
        if self.main_hash_justified:
            resize_factor = (1 + BIR) / (1 + BP * (3 + non_vote_frac / (1 - min(non_vote_frac, 0.5))))
        else:
            resize_factor = (1 + BIR) / (1 + BP * (2 + non_vote_frac / (1 - min(non_vote_frac, 0.5))))
    else:
        # If either current or prev dynasty is empty, then pay no interest, and all hashes justify and finalize
        resize_factor = 1
        self.main_hash_justified = True
        self.main_hash_finalized = True
        self.consensus_messages[epoch - 1].checkpoint_hash_justified[self.checkpoint_hashes[epoch - 1]] = True
    # Debugging
    self.latest_nvf = non_vote_frac
    self.latest_resize_factor = resize_factor
    # Set the epoch number
    self.current_epoch = epoch
    # Adjust counters for interest
    self.deposit_scale_factor[epoch] = self.deposit_scale_factor[epoch - 1] * resize_factor
    # Increment the dynasty (if there are no validators yet, then all hashes finalize)
    if self.main_hash_finalized:
        self.dynasty += 1
        self.total_prevdyn_deposits = self.total_curdyn_deposits
        self.total_curdyn_deposits += self.next_dynasty_wei_delta
        self.next_dynasty_wei_delta = self.second_next_dynasty_wei_delta
        self.second_next_dynasty_wei_delta = 0
        self.dynasty_start_epoch[self.dynasty] = epoch
    self.dynasty_in_epoch[epoch] = self.dynasty
    # Set the checkpoint hash for this epoch
    self.checkpoint_hashes[epoch] = blockhash(epoch * self.epoch_length - 1)
    if self.main_hash_justified:
        self.expected_source_epoch = epoch - 1
    self.main_hash_justified = False
    self.main_hash_finalized = False

# Send a deposit to join the validator set
@payable
def deposit(validation_addr: address, withdrawal_addr: address):
    assert self.current_epoch == block.number / self.epoch_length
    assert extract32(raw_call(self.purity_checker, concat('\xa1\x90>\xab', as_bytes32(validation_addr)), gas=500000, outsize=32), 0) != as_bytes32(0)
    self.validators[self.nextValidatorIndex] = {
        deposit: msg.value / self.deposit_scale_factor[self.current_epoch],
        dynasty_start: self.dynasty + 2,
        dynasty_end: 1000000000000000000000000000000,
        addr: validation_addr,
        withdrawal_addr: withdrawal_addr,
        prev_vote_epoch: 0,
    }
    self.nextValidatorIndex += 1
    self.second_next_dynasty_wei_delta += msg.value / self.deposit_scale_factor[self.current_epoch]

# Log in or log out from the validator set. A logged out validator can log
# back in later, if they do not log in for an entire withdrawal period,
# they can get their money out
def logout(logout_msg: bytes <= 1024):
    assert self.current_epoch == block.number / self.epoch_length
    # Get hash for signature, and implicitly assert that it is an RLP list
    # consisting solely of RLP elements
    sighash = extract32(raw_call(self.sighasher, logout_msg, gas=200000, outsize=32), 0)
    # Extract parameters
    values = RLPList(logout_msg, [num, num, bytes])
    validator_index = values[0]
    epoch = values[1]
    sig = values[2]
    # Signature check
    assert extract32(raw_call(self.validators[validator_index].addr, concat(sighash, sig), gas=500000, outsize=32), 0) == as_bytes32(1)
    # Check that we haven't already withdrawn
    assert self.validators[validator_index].dynasty_end >= self.dynasty + 2
    # Set the end dynasty
    self.validators[validator_index].dynasty_end = self.dynasty + 2
    self.second_next_dynasty_wei_delta -= self.validators[validator_index].deposit

# Gets validator's current deposit size
@constant
def get_deposit_size(validator_index: num) -> num(wei):
    return floor(self.validators[validator_index].deposit * self.deposit_scale_factor[self.current_epoch])

@constant
def get_total_curdyn_deposits() -> wei_value:
    return floor(self.total_curdyn_deposits * self.deposit_scale_factor[self.current_epoch])

@constant
def get_total_prevdyn_deposits() -> wei_value:
    return floor(self.total_prevdyn_deposits * self.deposit_scale_factor[self.current_epoch])

# Removes a validator from the validator pool
@internal
def delete_validator(validator_index: num):
    if self.validators[validator_index].dynasty_end > self.dynasty + 2:
        self.next_dynasty_wei_delta -= self.validators[validator_index].deposit
    self.validators[validator_index] = {
        deposit: 0,
        dynasty_start: 0,
        dynasty_end: 0,
        addr: None,
        withdrawal_addr: None,
        prev_vote_epoch: 0,
    }

# Withdraw deposited ether
def withdraw(validator_index: num):
    # heck that we can withdraw
    assert self.dynasty >= self.validators[validator_index].dynasty_end + 1
    end_epoch = self.dynasty_start_epoch[self.validators[validator_index].dynasty_end + 1]
    assert self.current_epoch >= end_epoch + self.withdrawal_delay
    # Withdraw
    withdraw_amount = floor(self.validators[validator_index].deposit * self.deposit_scale_factor[end_epoch])
    send(self.validators[validator_index].withdrawal_addr, withdraw_amount)
    self.delete_validator(validator_index)

# Helper functions that clients can call to know what to vote
@constant
def get_recommended_checkpoint_hash() -> bytes32:
    return self.checkpoint_hashes[self.current_epoch]

@constant
def get_recommended_source_epoch() -> num:
    return self.expected_source_epoch

# Reward the given validator, and reflect this in total deposit figured
def proc_reward(validator_index: num, reward: num(wei/m)):
    start_epoch = self.dynasty_start_epoch[self.validators[validator_index].dynasty_start]
    self.validators[validator_index].deposit += reward
    ds = self.validators[validator_index].dynasty_start
    de = self.validators[validator_index].dynasty_end
    dc = self.dynasty
    dp = dc - 1
    if ((ds <= dc) and (dc < de)):
        self.total_curdyn_deposits += reward
    if ((ds <= dp) and (dp < de)):
        self.total_prevdyn_deposits += reward
    if dc == de - 1:
        self.next_dynasty_wei_delta -= reward
    if dc == de - 2:
        self.second_next_dynasty_wei_delta -= reward
    

# Process a vote message
def vote(vote_msg: bytes <= 1024):
    # Get hash for signature, and implicitly assert that it is an RLP list
    # consisting solely of RLP elements
    sighash = extract32(raw_call(self.sighasher, vote_msg, gas=200000, outsize=32), 0)
    # Extract parameters
    values = RLPList(vote_msg, [num, num, bytes32, num, bytes])
    validator_index = values[0]
    epoch = values[1]
    vote_hash = values[2]
    source_epoch = values[3]
    sig = values[4]
    # Check the signature
    assert extract32(raw_call(self.validators[validator_index].addr, concat(sighash, sig), gas=500000, outsize=32), 0) == as_bytes32(1)
    # Check that we are in the right epoch
    assert epoch <= self.current_epoch
    assert epoch <= block.number / self.epoch_length
    # Check that the source epoch is before the epoch
    assert source_epoch < epoch
    # Check that the checkpoint hash is correct
    assert self.checkpoint_hashes[epoch] == vote_hash
    # Check that this vote has not yet been made
    assert not bitwise_and(self.consensus_messages[epoch].vote_bitmap[vote_hash][validator_index / 256],
                           shift(as_num256(1), validator_index % 256))
    # Original starting dynasty of the validator; fail if before
    ds = self.validators[validator_index].dynasty_start
    # Ending dynasty of the current login period
    de = self.validators[validator_index].dynasty_end
    # Dynasty of the vote
    dc = self.dynasty_in_epoch[epoch]
    dp = dc - 1
    in_current_dynasty = ((ds <= dc) and (dc < de))
    in_prev_dynasty = ((ds <= dp) and (dp < de))
    assert in_current_dynasty or in_prev_dynasty
    # Pay the reward if the vote was submitted in time with the correct data
    if self.epoch_justified_links[epoch][source_epoch] == True:
        reward = floor(self.validators[validator_index].deposit * self.current_penalty_factor * 2)
        self.proc_reward(validator_index, reward)
        # Pay the reward if the checkpoint hash got finalized
        if self.epoch_justified_links[source_epoch][source_epoch - 1] == True:
            reward = floor(self.validators[validator_index].deposit * self.current_penalty_factor)
            self.proc_reward(validator_index, reward)
    # Can't vote for this epoch again
    self.consensus_messages[epoch].vote_bitmap[vote_hash][validator_index / 256] = \
        bitwise_or(self.consensus_messages[epoch].vote_bitmap[vote_hash][validator_index / 256],
            shift(as_num256(1), validator_index % 256))
    # Record that this vote took place
    self.validators[validator_index].prev_vote_epoch = epoch
    curdyn_votes = self.consensus_messages[epoch].cur_dyn_votes[vote_hash]
    if in_current_dynasty:
        curdyn_votes += self.validators[validator_index].deposit
        self.consensus_messages[epoch].cur_dyn_votes[vote_hash] = curdyn_votes
    prevdyn_votes = self.consensus_messages[epoch].prev_dyn_votes[vote_hash]
    if in_prev_dynasty:
        prevdyn_votes += self.validators[validator_index].deposit
        self.consensus_messages[epoch].prev_dyn_votes[vote_hash] = prevdyn_votes
    # If enough votes with the same source_epoch and hash are made,
    # then the hash value is justified for vote
    if (curdyn_votes >= self.total_curdyn_deposits * 2 / 3 and \
            prevdyn_votes >= self.total_prevdyn_deposits * 2 / 3) and \
            not self.consensus_messages[epoch].checkpoint_hash_justified[vote_hash]:
        self.consensus_messages[epoch].checkpoint_hash_justified[vote_hash] = True
        if epoch == self.current_epoch:
            self.main_hash_justified = True
            self.epoch_justified_links[epoch][source_epoch] = True
            if ((not self.main_hash_finalized and source_epoch == epoch - 1) and \
                    self.last_justified_epoch == source_epoch):
                self.main_hash_finalized = True
                self.last_finalized_epoch = epoch
            self.last_justified_epoch = epoch
    raw_log([self.vote_log_topic], vote_msg)

@constant
def get_main_hash_voted_frac() -> decimal:
    checkpoint_hash = self.checkpoint_hashes[self.current_epoch]
    return min(self.consensus_messages[self.current_epoch].cur_dyn_votes[checkpoint_hash] / self.total_curdyn_deposits,
               self.consensus_messages[self.current_epoch].prev_dyn_votes[checkpoint_hash] / self.total_prevdyn_deposits)

# Cannot make two prepares in the same epoch
def double_vote_slash(vote1: bytes <= 1000, vote2: bytes <= 1000):
    # Get hash for signature, and implicitly assert that it is an RLP list
    # consisting solely of RLP elements
    sighash1 = extract32(raw_call(self.sighasher, vote1, gas=200000, outsize=32), 0)
    sighash2 = extract32(raw_call(self.sighasher, vote2, gas=200000, outsize=32), 0)
    # Check that they're not the same message
    assert sighash1 != sighash2
    # Extract parameters
    values1 = RLPList(vote1, [num, num, bytes32, num, bytes])
    values2 = RLPList(vote2, [num, num, bytes32, num, bytes])
    # Check that validator is the same
    validator_index = values1[0]
    assert validator_index == values2[0]
    # Check that they're from the same epoch
    epoch1 = values1[1]
    assert epoch1 == values2[1]
    # Check that the checkpoint hashes are different
    checkpoint_hash1 = values1[2]
    assert checkpoint_hash1 != values2[2]
    # Check the signatures
    sig1 = values1[4]
    sig2 = values2[4]
    assert extract32(raw_call(self.validators[validator_index].addr, concat(sighash1, sig1), gas=500000, outsize=32), 0) == as_bytes32(1)
    assert extract32(raw_call(self.validators[validator_index].addr, concat(sighash2, sig2), gas=500000, outsize=32), 0) == as_bytes32(1)
    # Delete the offending validator, and give a 4% "finder's fee"
    validator_deposit = self.get_deposit_size(validator_index)
    send(msg.sender, validator_deposit / 25)
    self.total_destroyed += validator_deposit * 24 / 25
    self.delete_validator(validator_index)

def surround_slash(vote1: bytes <= 1024, vote2: bytes <= 1024):
    # Get hash for signature, and implicitly assert that it is an RLP list
    # consisting solely of RLP elements
    sighash1 = extract32(raw_call(self.sighasher, vote1, gas=200000, outsize=32), 0)
    sighash2 = extract32(raw_call(self.sighasher, vote2, gas=200000, outsize=32), 0)
    # Check that they're not the same message
    assert sighash1 != sighash2
    # Extract parameters
    values1 = RLPList(vote1, [num, num, bytes32, num, bytes])
    values2 = RLPList(vote2, [num, num, bytes32, num, bytes])
    # Check that validator is the same
    validator_index = values1[0]
    assert validator_index == values2[0]
    vote1_epoch = values1[1]
    vote2_epoch = values2[1]
    vote1_source = values1[3]
    vote2_source = values2[3]
    sig1 = values1[4]
    sig2 = values2[4]
    # Check the signatures
    assert extract32(raw_call(self.validators[validator_index].addr, concat(sighash1, sig1), gas=500000, outsize=32), 0) == as_bytes32(1)
    assert extract32(raw_call(self.validators[validator_index].addr, concat(sighash2, sig2), gas=500000, outsize=32), 0) == as_bytes32(1)
    # Check that the vote refers to something older
    if vote1_epoch > vote2_epoch:
        assert vote1_source < vote2_source
    elif vote1_epoch < vote2_epoch:
        assert vote1_source > vote2_source
    # Delete the offending validator, and give a 4% "finder's fee"
    validator_deposit = self.get_deposit_size(validator_index)
    send(msg.sender, validator_deposit / 25)
    self.total_destroyed += validator_deposit * 24 / 25
    self.delete_validator(validator_index)

# Temporary backdoor for testing purposes (to allow recovering destroyed deposits)
def owner_withdraw():
    send(self.owner, self.total_destroyed)
    self.total_destroyed = 0

# Change backdoor address (set to zero to remove entirely)
def change_owner(new_owner: address):
    if self.owner == msg.sender:
        self.owner = new_owner
