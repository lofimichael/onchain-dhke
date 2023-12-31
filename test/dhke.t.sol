// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/Vm.sol";
import "../src/dhke.sol";
import "../src/interfaces/IDHKE.sol";

contract DHKE_Test is Test {
    Exchanger public DHKE;

    address dummy = 0x0000000000000000000000000000000000001337;
    address dummier = 0x0000000000000000000000000000000000001338;
    address owner = 0x0000000000000000000000000000000000042069;

    // set default generator and primehex, and deploy the DHKE contract
    function setUp() public {
        /// @notice 8192-bit MODP Group -- hex value exactly per RFC-3526 -- https://www.ietf.org/rfc/rfc3526.txt
        string
            memory primehex = "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D 670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7 88719A10 BDBA5B26 99C32718 6AF4E23C 1A946834 B6150BDA 2583E9CA 2AD44CE8 DBBBC2DB 04DE8EF9 2E8EFC14 1FBECAA6 287C5947 4E6BC05D 99B2964F A090C3A2 233BA186 515BE7ED 1F612970 CEE2D7AF B81BDD76 2170481C D0069127 D5B05AA9 93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34028492 36C3FAB4 D27C7026 C1D4DCB2 602646DE C9751E76 3DBA37BD F8FF9406 AD9E530E E5DB382F 413001AE B06A53ED 9027D831 179727B0 865A8918 DA3EDBEB CF9B14ED 44CE6CBA CED4BB1B DB7F1447 E6CC254B 33205151 2BD7AF42 6FB8F401 378CD2BF 5983CA01 C64B92EC F032EA15 D1721D03 F482D7CE 6E74FEF6 D55E702F 46980C82 B5A84031 900B1C9E 59E7C97F BEC7E8F3 23A97A7E 36CC88BE 0F1D45B7 FF585AC5 4BD407B2 2B4154AA CC8F6D7E BF48E1D8 14CC5ED2 0F8037E0 A79715EE F29BE328 06A1D58B B7C5DA76 F550AA3D 8A1FBFF0 EB19CCB1 A313D55C DA56C9EC 2EF29632 387FE8D7 6E3C0468 043E8F66 3F4860EE 12BF2D5B 0B7474D6 E694F91E 6DBE1159 74A3926F 12FEE5E4 38777CB6 A932DF8C D8BEC4D0 73B931BA 3BC832B6 8D9DD300 741FA7BF 8AFC47ED 2576F693 6BA42466 3AAB639C 5AE4F568 3423B474 2BF1C978 238F16CB E39D652D E3FDB8BE FC848AD9 22222E04 A4037C07 13EB57A8 1A23F0C7 3473FC64 6CEA306B 4BCBC886 2F8385DD FA9D4B7F A2C087E8 79683303 ED5BDD3A 062B3CF5 B3A278A6 6D2A13F8 3F44F82D DF310EE0 74AB6A36 4597E899 A0255DC1 64F31CC5 0846851D F9AB4819 5DED7EA1 B1D510BD 7EE74D73 FAF36BC3 1ECFA268 359046F4 EB879F92 4009438B 481C6CD7 889A002E D5EE382B C9190DA6 FC026E47 9558E447 5677E9AA 9E3050E2 765694DF C81F56E8 80B96E71 60C980DD 98EDD3DF FFFFFFFF FFFFFFFF";

        /// @notice Diffie-Hellman generator -- modulus to calculate remainder (generator^privateKey % prime -> publicKey)
        uint256 generator = 2;

        vm.startPrank(owner);
        DHKE = new Exchanger(generator, primehex);
        vm.stopPrank();
    }

    function test_Deploy() public {
        assertTrue(address(DHKE) != address(0));
        console2.log("DHKE address: ", address(DHKE));
        console2.log("DHKE owner: ", DHKE.owner());
        console2.log("msg.sender:", msg.sender);
    }

    // test to update constants with short dummy values
    function test_UpdateConstants() public {
        vm.prank(owner);
        DHKE.updateConstants(
            2,
            "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B",
            "https://www.ietf.org/rfc/rfc3526.txt"
        );
    }

    // test to update constants as non-owner
    function testFail_UpdateConstants() public {
        console2.log("requiring msg.sender == ", DHKE.owner());
        vm.startPrank(dummy);
        console2.log("pranking as dummy:", dummy);
        DHKE.updateConstants(
            2,
            "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B",
            "https://www.ietf.org/rfc/rfc3526.txt"
        );
        vm.stopPrank();
    }

    // test to set a public key as respective owners
    function test_setPublicKey() public {
        vm.prank(dummy);
        DHKE.setPublicKey("dummyPublicKey");
        vm.prank(dummier);
        DHKE.setPublicKey("dummierPublicKey");
    }

    // register a payload without a public key for the sender
    function testFail_sendNoPKPayloadSender() public {
        vm.startPrank(dummy);
        DHKE.registerEncryptedPayload(
            dummy,
            dummier,
            "encryptedBase64DataThatOnlyRecipientCanDecrypt",
            "checksum",
            0,
            0
        );
        vm.stopPrank();
    }

    // register a payload without a public key for the recipient
    function testFail_sendNoPKPayloadRecipient() public {
        vm.startPrank(dummy);
        DHKE.setPublicKey("dummy's public key");
        DHKE.registerEncryptedPayload(
            dummy,
            dummier,
            "encryptedBase64DataThatOnlyRecipientCanDecrypt",
            "checksum",
            0,
            0
        );
        vm.stopPrank();
    }

    // fail the payload transaction outright if the sender is not the msg.sender
    function testFail_sendNotSenderPayload() public {
        vm.startPrank(dummier);
        DHKE.registerEncryptedPayload(
            dummy,
            dummier,
            "encryptedBase64DataThatOnlyRecipientCanDecrypt",
            "checksum",
            0,
            0
        );
    }

    function test_registerPayload() public {
        // register public keys for each user
        vm.prank(dummy);
        DHKE.setPublicKey("dummy's public key");
        vm.prank(dummier);
        DHKE.setPublicKey("dummier's public key");

        vm.startPrank(dummy);

        DHKE.registerEncryptedPayload(
            dummy,
            dummier,
            "data1",
            "checksum1",
            0,
            1
        );

        DHKE.registerEncryptedPayload(
            dummy,
            dummier,
            "data2",
            "checksum2",
            0,
            1
        );

        vm.stopPrank();

        // get the payload for the first nonce and assert it's data is equal to the data we sent;
        console2.log(DHKE.getEncryptedPayload(dummy, dummier, 0).encryptedData);
        assertEq(
            DHKE.getEncryptedPayload(dummy, dummier, 0).encryptedData,
            "data1"
        );
    }

    function test_getPayload() public {
        // register public keys for each user
        vm.prank(dummy);
        DHKE.setPublicKey("dummy's public key");
        vm.prank(dummier);
        DHKE.setPublicKey("dummier's public key");

        vm.prank(dummy);
        DHKE.registerEncryptedPayload(
            dummy,
            dummier,
            "data1",
            "checksum1",
            0,
            1
        );

        vm.prank(dummy);
        DHKE.registerEncryptedPayload(
            dummy,
            dummier,
            "data2",
            "checksum2",
            0,
            1
        );

        vm.prank(dummier);
        DHKE.registerEncryptedPayload(
            dummier,
            dummy,
            "data3",
            "checksum3",
            0,
            1
        );

        DHKE.getEncryptedPayload(dummy, dummier, 0);
        DHKE.getEncryptedPayload(dummy, dummier, 1);
        DHKE.getEncryptedPayload(dummier, dummy, 0);
        console2.log(DHKE.getEncryptedPayload(dummy, dummier, 0).encryptedData);
        console2.log(DHKE.getEncryptedPayload(dummy, dummier, 1).encryptedData);
        console2.log(DHKE.getEncryptedPayload(dummier, dummy, 0).encryptedData);
        assertEq(
            DHKE.getEncryptedPayload(dummy, dummier, 0).encryptedData,
            "data1"
        );
        assertEq(
            DHKE.getEncryptedPayload(dummy, dummier, 1).encryptedData,
            "data2"
        );
        assertEq(
            DHKE.getEncryptedPayload(dummier, dummy, 0).encryptedData,
            "data3"
        );
    }

    function testFail_getNullPayload() public {
        // register public keys for each user
        vm.prank(dummy);
        DHKE.setPublicKey("dummy's public key");
        vm.prank(dummier);
        DHKE.setPublicKey("dummier's public key");

        vm.prank(dummy);
        DHKE.registerEncryptedPayload(
            dummy,
            dummier,
            "data1",
            "checksum1",
            0,
            1
        );

        // attempt to get the data of a sender/receiver pair within normal nonce ranges
        DHKE.getEncryptedPayload(dummy, dummier, 0);

        // attempt to get the data of a nonce not yet reached
        DHKE.getEncryptedPayload(dummy, dummier, 9001);
    }

    function test_verifyChecksumIsEqual() public {
        // register public keys for each user
        vm.prank(dummy);
        DHKE.setPublicKey("dummy's public key");
        vm.prank(dummier);
        DHKE.setPublicKey("dummier's public key");

        vm.prank(dummy);
        DHKE.registerEncryptedPayload(
            dummy,
            dummier,
            "data1",
            "checksum1",
            0,
            1
        );

        vm.prank(dummy);
        DHKE.registerEncryptedPayload(
            dummy,
            dummier,
            "data2",
            "checksum2",
            1,
            2
        );

        vm.prank(dummier);

        DHKE.registerEncryptedPayload(
            dummier,
            dummy,
            "data3",
            "checksum3",
            0,
            1
        );

        // get the payload for the first nonce and assert it's data is equal to the data we sent;
        assertEq(
            DHKE.getEncryptedPayload(dummy, dummier, 0).encryptedData,
            "data1"
        );
        assertEq(
            DHKE.getEncryptedPayload(dummy, dummier, 1).encryptedData,
            "data2"
        );
        assertEq(
            DHKE.getEncryptedPayload(dummier, dummy, 0).encryptedData,
            "data3"
        );

        // get the payload for the first nonce and assert it's checksum is equal to the checksum we sent;
        assertEq(
            DHKE.getEncryptedPayload(dummy, dummier, 0).checksum,
            "checksum1"
        );
        assertEq(
            DHKE.getEncryptedPayload(dummy, dummier, 1).checksum,
            "checksum2"
        );
        assertEq(
            DHKE.getEncryptedPayload(dummier, dummy, 0).checksum,
            "checksum3"
        );

        // verify the checksums are equal
        assertEq(DHKE.verifyData(dummy, dummier, 0, "checksum1"), true);
        assertEq(DHKE.verifyData(dummy, dummier, 1, "checksum2"), true);
        assertEq(DHKE.verifyData(dummier, dummy, 0, "checksum3"), true);
    }

    function testPayloadsByChecksum() public {
        vm.startPrank(dummy);
        DHKE.setPublicKey("dummy's public key");
        vm.stopPrank();

        vm.startPrank(dummier);
        DHKE.setPublicKey("dummier's public key");
        vm.stopPrank();

        bytes32 checksum1 = keccak256(abi.encodePacked("checksum1"));

        vm.startPrank(dummy);
        DHKE.registerEncryptedPayload(dummy, dummier, "data1", checksum1, 0, 1);
        vm.stopPrank();

        IDHKE.DataPayload[] memory payloads = DHKE.getPayloadsByChecksum(
            checksum1
        );
        assertEq(payloads.length, 1);
        assertEq(payloads[0].encryptedData, "data1");
    }

    function testPayloadsBySender() public {
        bytes32 checksum1 = keccak256(abi.encodePacked("checksum1"));
        bytes32 checksum2 = keccak256(abi.encodePacked("checksum2"));

        vm.startPrank(dummy);
        DHKE.setPublicKey("dummy's public key");
        vm.stopPrank();

        vm.startPrank(dummier);
        DHKE.setPublicKey("dummier's public key");
        vm.stopPrank();

        // Register two payloads from the same sender
        vm.startPrank(dummy);
        DHKE.registerEncryptedPayload(dummy, dummier, "data1", checksum1, 0, 1);
        DHKE.registerEncryptedPayload(dummy, dummier, "data2", checksum2, 1, 2);
        vm.stopPrank();

        bytes32[] memory senderPayloads = DHKE.getChecksumsBySender(dummy);
        assertEq(senderPayloads.length, 2);
        assertEq(senderPayloads[0], checksum1); // confirm that dummy sent checksum1
        assertEq(senderPayloads[1], checksum2); // confirm that dummy sent checksum2
    }

    function testPayloadsByRecipient() public {
        bytes32 checksum1 = keccak256(abi.encodePacked("checksum1"));
        bytes32 checksum2 = keccak256(abi.encodePacked("checksum2"));

        vm.startPrank(dummy);
        DHKE.setPublicKey("dummy's public key");
        vm.stopPrank();

        vm.startPrank(dummier);
        DHKE.setPublicKey("dummier's public key");
        vm.stopPrank();

        vm.startPrank(dummy);
        DHKE.registerEncryptedPayload(dummy, dummier, "data1", checksum1, 0, 1);
        vm.stopPrank();

        vm.startPrank(dummier);
        DHKE.registerEncryptedPayload(dummier, dummy, "data2", checksum2, 1, 2);
        vm.stopPrank();

        bytes32[] memory recipientPayloads = DHKE.getChecksumsByRecipient(
            dummy
        );
        assertEq(recipientPayloads.length, 1);
        assertEq(recipientPayloads[0], checksum2); // confirm that dummy is the recipient of checksum2 from dummier
    }
}
