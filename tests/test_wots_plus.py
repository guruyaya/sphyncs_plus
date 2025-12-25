from spyncs_plus.components.wots_plus import (WotsPlusPublic, WotsPlusSecret)
from spyncs_plus.helpers.hashers import SHA256Hasher
from spyncs_plus.helpers.random_generators import CSPRNGRandomGenerator

def test_wots_public_init():
    pass

def test_wots_secret_init():
    generator = CSPRNGRandomGenerator().setup(123)
    hasher = SHA256Hasher()
    wots = WotsPlusSecret(hasher, generator)

    assert wots.randomGen is generator
    assert wots.hasher is hasher
    assert wots.version == "1.0a"

def test_wots_plus_secret_verify():
    message_to_sign = b"Hello World"
    fake_message_to_sign = b"Hello world"

    wots1 = WotsPlusSecret(SHA256Hasher(), CSPRNGRandomGenerator().setup(123))
    signature = wots1.sign(message_to_sign)
    wotsp1 = wots1.get_public_wots()

    wots2 = WotsPlusSecret(SHA256Hasher(), CSPRNGRandomGenerator().setup(120))
    signature_bad = wots2.sign(message_to_sign)
    
    assert wotsp1.public_key.hex() == "de3448c592f51d3c279edef9f4569c856a0faeadcad38beaf229d1c694a73538"
    assert (wotsp1.verify(message_to_sign, signature))
    assert (wotsp1.verify(message_to_sign, signature_bad) == False)
    assert (wotsp1.verify(fake_message_to_sign, signature) == False)

def test_wots_plus_public_verify():
    message_to_sign = b"Hello World"
    fake_message_to_sign = b"Hello world"
    public_key = bytes.fromhex("de3448c592f51d3c279edef9f4569c856a0faeadcad38beaf229d1c694a73538")
    bad_public_key = bytes.fromhex("ae3448c592f51d3c279edef9f4569c856a0faeadcad38beaf229d1c694a73538")
    
    signature = [
        '18eee5cebc0de207542b27b2b91699c0c31d01625f1a0456a4466226e10afe03', '2caca069d7d921e14c8c1aa8985d87791776012c5191aa17841e0f696fb94d11', 
        '5d3483584fd64ba8c05b82de1fe68597c63a9f3eea2356728f8352a2a602c70d', '9e440c184233a4a8cf0fa2f581e5601d98ea41d7d13d5fcd9d0e1ad9772aeb10', 
        'ba20b8817c52569eb3bb477e0f34aee3ad6c35defae4361825a0668d0456d26b', 'f29062c80b589ab72c472ec6e76e15f6f779c6f69303724603800b41113eb8d7', 
        '7e345cce56555a1f74a2efaeffd74f14a3a9f055dd7e415a152076086218556c', '0fe445b896ed44aa6d90d08db080ecf3588a86d781a8c33e8cbe254a9bda5ba5', 
        'e0e201483699f5cf3fcc37c0927915fe43ed9b7f65f2aa6ca86d1e82b5c8733c', 'a5bf68b2a3cc2590b85869e3af808dc6b0bbee705305d2f30d2fcff71c7fb672', 
        'eac2293b9d988d411c3cbcf8bdcd94f6552269ed37174ca7a96bf5b55cd32794', 'a5921804ed52e9b23924e8a4c19f4dfd3c133cbe2e9f67a10429bc4a5a220083', 
        '4180b9785034d3ef43342f6077388b554a4596b9a2dae9e8500e2c6e9ea83e5c', '3cfcb768066360807742358797d0aafe088c8676643d8214e0dfcf8706e4e0b4', 
        '5a0f93be894de6bcecaf026e0d659e612296e830e7e37676221ea29e21c983f8', 'd4d2f1d335cc4c1f8bdfbfcbe8276193448544206c9211671b4b045bd7d8ea3e', 
        '3aa5213a827fd68c575fd5807c2843c9f9be971391ac2c45d9148627b06fa0c7', 'cc9876c0ef07d2c73e3af9c3e6a6a500ef45808eeb11d5c0099e5f757144d6bb', 
        'bee5032d08dd2b644fce1c185c004afcd1de4d7052477764c909daed20234690', '8f99dc322231b6a997b7dfd3440419ede32c5ed6ffe4e2d5c9fb6bd16e3076ff', 
        'fdede54ee00f6961ea8bca17ad65cc87c9dbf49fa68c440c832f39031d76b0ea', 'ee4e6affa58f9a7b476c6200872afbba90e3d02bbfc44bc810ada5713d619676', 
        'a7c8aed6f60031e58dcbb364a533bda20d88e853325e9d78576d0a2d5c930058', 'f6c6dfb2dbedf005eed56f66593a4e31682ffd6418a081ee1ddb36c812b7793e', 
        'e3fe6eaff8327c84099752dc651c17991b278f1fe0574a00cf1386069b22eca6', '367d9874a21f799b009a9312bfc8bb378485a87a470b8154ed4d8cef02ea10d1', 
        'eaad862737eb7373f65e24824080cdc64d281776a0059031b7f6d66ea9b71dd5', '1ff8020e368c43baa01888df9d0a65b5ecd8010a28b8deebac686787226309d5', 
        '8579f0b3c3ebc4d72e910fae9ca8fb22689aa3337a7fcce752fa890dfb7f6b21', '9f66f76d29dcb3e46242b04598d09d032bd251b1e25af2cd8fecc931abb35352', 
        '45ce3571947e08e7fe9daf9851cdebf38deeb1a2958e7a7058d07cc6e7f274da', 'f09ea6cc6e22ccc89d6324a6814318f973ced411f898c621a0673a7a1efd4759',
        '92d6de5c2dfc0a2f61ee0f0eb27251db82c8a27ed2463e08592cd31d89cb9050', '97a49e93742191b5d51106233bba0d524dbe73fa24df500664fbb9eae9a996f0'
    ]
    good_signature = [bytes.fromhex(h) for h in signature]
    signature[3] = signature[3][:9] + '0' + signature[3][10:]
    bad_signature = [bytes.fromhex(h) for h in signature]

    wots_good = WotsPlusPublic(SHA256Hasher(), public_key)
    wots_bad = WotsPlusPublic(SHA256Hasher(), bad_public_key)

    assert wots_good.verify(message_to_sign, good_signature)
    assert wots_good.verify(message_to_sign, bad_signature) is False
    assert wots_bad.verify(message_to_sign, good_signature) is False
    assert wots_good.verify(fake_message_to_sign, good_signature) is False
