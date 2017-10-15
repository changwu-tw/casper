import rlp
from ethereum.tools import tester as t
from ethereum import utils, common, transactions, abi
from casper_tester_helper_functions import mk_initializers, casper_config, \
    new_epoch, custom_chain, viper_rlp_decoder_address, sig_hasher_address, \
    purity_checker_address, casper_abi, purity_checker_abi
from viper import compiler
import serpent
from ethereum.slogging import LogRecorder, configure_logging, set_level
config_string = ':info,eth.vm.log:trace,eth.vm.op:trace,eth.vm.stack:trace,eth.vm.exit:trace,eth.pb.msg:trace,eth.pb.tx:debug'
# configure_logging(config_string=config_string)

alloc = {}
alloc[t.a0] = {'balance': 100000 * utils.denoms.ether}
# alloc[t.a1] = {'balance': 10**22}
s = custom_chain(t, alloc, 9999999, 4707787, 2000000)

EPOCH_LENGTH = casper_config["epoch_length"]

code_template = """
~calldatacopy(0, 0, 128)
~call(3000, 1, 0, 0, 128, 0, 32)
return(~mload(0) == %s)
"""


def mk_validation_code(address):
    return serpent.compile(code_template % (utils.checksum_encode(address)))


# Install Casper, RLP decoder, purity checker, sighasher
init_txs, casper_address = mk_initializers(casper_config, t.k0)
for tx in init_txs:
    if s.head_state.gas_used + tx.startgas > s.head_state.gas_limit:
        s.mine(1)
    s.direct_tx(tx)

ct = abi.ContractTranslator(purity_checker_abi)
# Check that the RLP decoding library and the sig hashing library are "pure"
assert utils.big_endian_to_int(s.tx(t.k0, purity_checker_address, 0, ct.encode('submit', [viper_rlp_decoder_address]))) == 1
assert utils.big_endian_to_int(s.tx(t.k0, purity_checker_address, 0, ct.encode('submit', [sig_hasher_address]))) == 1


casper = t.ABIContract(s, casper_abi, casper_address)
s.mine(1)


# Helper functions for making a prepare, commit, login and logout message
def mk_vote(validator_index, epoch, checkpoint_hash, source_epoch, key):
    sighash = utils.sha3(rlp.encode([validator_index, epoch, checkpoint_hash, source_epoch]))
    v, r, s = utils.ecdsa_raw_sign(sighash, key)
    sig = utils.encode_int32(v) + utils.encode_int32(r) + utils.encode_int32(s)
    return rlp.encode([validator_index, epoch, checkpoint_hash, source_epoch, sig])


def mk_logout(validator_index, epoch, key):
    sighash = utils.sha3(rlp.encode([validator_index, epoch]))
    v, r, s = utils.ecdsa_raw_sign(sighash, key)
    sig = utils.encode_int32(v) + utils.encode_int32(r) + utils.encode_int32(s)
    return rlp.encode([validator_index, epoch, sig])


def induct_validator(casper, key, value):
    valcode_addr = s.tx(key, "", 0, mk_validation_code(utils.privtoaddr(key)))
    assert utils.big_endian_to_int(s.tx(key, purity_checker_address, 0, ct.encode('submit', [valcode_addr]))) == 1
    casper.deposit(valcode_addr, utils.privtoaddr(key), value=value)


# Begin the test
print("Starting tests")
# Initialize the first epoch
current_dyn, _e, _c, _se = new_epoch(s, casper, EPOCH_LENGTH)
assert casper.get_nextValidatorIndex() == 0
assert casper.get_current_epoch() == 1
print("Epoch initialized")

# Deposit one validator
induct_validator(casper, t.k1, 200 * 10**18)
# Mine two epochs
current_dyn, _e, _c, _se = new_epoch(s, casper, EPOCH_LENGTH)
current_dyn, _e, _c, _se = new_epoch(s, casper, EPOCH_LENGTH)
assert casper.get_total_curdyn_deposits() == 200 * 10**18
assert casper.get_total_prevdyn_deposits() == 0

# Send a vote message
print('pre deposit', casper.get_deposit_size(0), casper.get_total_curdyn_deposits())
assert casper.get_deposit_size(0) == casper.get_total_curdyn_deposits()
casper.vote(mk_vote(0, _e, _c, _se, t.k1))
print('Gas consumed for a prepare: %d' % s.last_gas_used(with_tx=True))
assert casper.get_main_hash_justified()
print("Vote message processed")
try:
    casper.vote(mk_vote(0, 1, '\x35' * 32, '\x00' * 32, 0, t.k0))
    success = True
except:
    success = False
assert not success
print("Vote message fails the second time")