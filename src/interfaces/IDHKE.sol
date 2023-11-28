// SPDX-License-Identifier: MIT

/**
                            ,-.                                             
       ___,---.__          /'|`\          __,---,___                        
    ,-'    \`    `-.____,-'  |  `-.____,-'    //    `-.                     
  ,'        |           ~'\     /`~           |        `.                   
 /      ___//              `. ,'          ,  , \___      \                  
|    ,-'   `-.__   _         |        ,    __,-'   `-.    |                 
|   /          /\_  `   .    |    ,      _/\          \   |                 
\  |           \ \`-.___ \   |   / ___,-'/ /           |  /                 
 \  \           | `._   `\\  |  //'   _,' |           /  /                  
  `-.\         /'  _ `---'' , . ``---' _  `\         /,-'                   
     ``       /     \    ,='/ \`=.    /     \       ''                      
             |__   /|\_,--.,-.--,--._/|\   __|                              
             /  `./  \\`\ |  |  | /,//' \,'  \                              
            /   /     ||--+--|--+-/-|     \   \                             
           |   |     /'\_\_\ | /_/_/`\     |   |                            
            \   \__, \_     `~'     _/ .__/   /                             
             `-._,-'   `-._______,-'   `-._,-'                              
     _____               '           '                                      
  __|_    |__    _____    ______    ____    ┬──┬ ノ(ò_óノ)                   
 |    |      |  /     \  |   ___|  |    |                                   
 |    |_     |  |     |  |   ___|  |    |      (╯°□°)╯︵ ┻━┻ ︵ ╯(°□° ╯)     
 |______|  __|  \_____/  |___|     |____|   (⌐■_■)︻╦╤─ (╥﹏╥)               
    |_____|        	                                                        
  __  __  __    __   _    ______      __   _    ______    _____     ______  
 |  \/  \|  |  |  | | |  |___   |    |  |_| |  |   ___|  |     |   |   ___| 
 |     /\   |  |  |_| |   .-`.-`     |   _  |  |   ___|  |     \   |   ___| 
 |____/  \__|  |______|  |______|    |__| |_|  |______|  |__|\__\  |______| 
                                                           (っ^з^)♪♬         
                     	( •_•)O*¯`·.¸.·´¯`°Q(•_• )                          
@title Diffie Hellman Key Exchange (DHKE) Interface (Public Decentralized Data Exchange) 1.0
@author: @lofimichael
*/

pragma solidity ^0.8.9;

interface IDHKE {
    /// @notice -- DHKE Constants

    /// @notice -- convert to elliptic-curve DHKE
    struct PublicConstants {
        uint256 generator; // 2
        string primehex; // "FFFFFFFF FFFFFFFF C90FDAA2 ... ... ...98EDD3DF FFFFFFFF FFFFFFFF"
        string source; // 8192-bit MODP Group -- hex value exactly per RFC-3526 -- https://datatracker.ietf.org/doc/html/draft-ietf-ipsec-ike-modp-groups-04 -- https://www.ietf.org/rfc/rfc3526.txt
    }

    struct DataPayload {
        address sender;
        address recipient;
        string encryptedData;
        bytes32 checksum;
        uint256 index;
        uint256 contentlength;
    }

    event constantsUpdated(
        uint256 indexed generator, // 2
        string indexed primehex, // "FFFFFFFF FFFFFFFF C90FDAA2 ... ... ...98EDD3DF FFFFFFFF FFFFFFFF"
        string source, // 8192-bit MODP Group -- hex value exactly per RFC-3526 --https://www.ietf.org/rfc/rfc3526.txt
        uint256 indexed version // incrementing 0, 1, 2, etc
    );

    event ownerUpdated(address indexed oldOwner, address indexed newOwner);

    /// @notice -- DHKE events

    /// @notice Public key is registered by a user
    /// @notice This event occurs on registration or change of a public key for a user
    event publicKeyRegistered(string indexed publicKey, address indexed owner);

    /// @notice Data is sent and ready to be decrypted by the recipient
    /// @notice When sender and recipient both have registered public keys and the sender registers an encrypted data/key pair for the receiver, this event is emitted
    event encryptedPayloadRegistered(
        address indexed sender,
        address indexed recipient,
        string encryptedData,
        bytes32 indexed checksum,
        uint256 chunkIndex,
        uint256 contentlength
    );

    /// @notice update the public constants
    /// @param _generator The modulus generator to calculate remainder (generator^privateKey % prime -> publicKey)
    /// @param _primehex The large hexadecimal prime number to use as a public constant in the Diffie-Hellman key exchangeq
    /// @param _source Literature source for the prime and generator (should be a secure academic source to track the origin of the prime and generator)
    /// @return bool Success status
    function updateConstants(
        uint256 _generator,
        string memory _primehex,
        string memory _source
    ) external returns (bool);

    /// @notice register an Ethereum public key for a user
    /// @param _publicKey The public key to register for the user
    /// @return bool Success status
    function setPublicKey(string memory _publicKey) external returns (bool);

    /// @notice register an encrypted data payload and an associated encrypted decryption key for a recipient
    /// @param _sender The address of the user sending the encrypted data
    /// @param _recipient The address of the user receiving the encrypted data
    /// @param _encryptedData The encrypted data payload to register for the recipient
    /// @param _checksum The checksum of the original data
    /// @param _chunkIndex The index of the chunk in the sequence
    /// @param _contentlength The total length of the original data
    function registerEncryptedPayload(
        address _sender,
        address _recipient,
        string memory _encryptedData,
        bytes32 _checksum,
        uint256 _chunkIndex,
        uint256 _contentlength
    ) external returns (bool);

    /// @notice View function to compare an off-chain computed hash with the on-chain stored hash
    /// @param _sender The address of the user sending the encrypted data
    /// @param _recipient The address of the user receiving the encrypted data
    /// @param _nonce The nonce of the encrypted data payload
    /// @param offChainDataHash The off-chain computed hash of the original data
    /// @return bool Comparison status
    function verifyData(
        address _sender,
        address _recipient,
        uint256 _nonce,
        bytes32 offChainDataHash
    ) external view returns (bool);

    /// @notice change the owner of the contract
    /// @param _newOwner The address of the new owner
    /// @return bool Success status
    function changeOwner(address _newOwner) external returns (bool);

    /// @notice Helper Getters (View Functions)

    /// @notice get the public constants
    /// @return PublicConstants The public constants
    function getConstants() external view returns (PublicConstants memory);

    /// @notice get the public key for a user
    /// @param _user The address of the user
    /// @return string The public key for the user
    function getPublicKey(address _user) external view returns (string memory);

    /// @notice get the encrypted data payload for a recipient
    /// @param _sender The address of the user sending the encrypted data
    /// @param _recipient The address of the user receiving the encrypted data
    /// @param _nonce The nonce of the encrypted data payload
    /// @return DataPayload The encrypted data payload
    function getEncryptedPayload(
        address _sender,
        address _recipient,
        uint256 _nonce
    ) external view returns (DataPayload memory);

    /// @notice get the current nonce for a recipient, given a sender
    /// @param _sender The address of the user sending the encrypted data
    /// @param _recipient The address of the user receiving the encrypted data
    /// @return uint256 The current nonce of the messenging between sender/recipient
    function getNonce(
        address _sender,
        address _recipient
    ) external view returns (uint256);

    /// @notice get the payloads sent for a given checksum
    /// @param _checksum The checksum of the original data
    /// @return DataPayload[] The encrypted data payloads
    function getPayloadsByChecksum(
        bytes32 _checksum
    ) external view returns (DataPayload[] memory);

    /// @notice get payloads sent by a given sender
    /// @param _sender The address of the user sending the encrypted data
    /// @return DataPayload[] The encrypted data payloads
    function getChecksumsBySender(
        address _sender
    ) external view returns (bytes32[] memory);

    /// @notice get payloads sent to a given recipient
    /// @param _recipient The address of the user receiving the encrypted data
    /// @return DataPayload[] The encrypted data payloads
    function getChecksumsByRecipient(
        address _recipient
    ) external view returns (bytes32[] memory);

    /// @notice get the current nonce for a sender, given a recipient
    /// @notice this measures the nonce of say, if the recipient sends back info
    /// @notice in a completely reciprocal relationship, both sender and receiver have equal nonces
    /// @param _sender The address of the user sending the encrypted data
    /// @param _recipient The address of the user receiving the encrypted data
    /// @return uint256 The current nonce of the encrypted data payload
    function getInverseNonce(
        address _sender,
        address _recipient
    ) external view returns (uint256);

    /// @notice get the owner of the contract
    /// @return address The address of the owner
    function getOwner() external view returns (address);
}
