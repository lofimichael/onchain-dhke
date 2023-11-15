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
@title Diffie Hellman Key Exchange (DHKE) Interface (Public Decentralized Data Exchange)
@author: @lofimichael
*/

pragma solidity ^0.8.9;

import { IDHKE } from "./interfaces/IDHKE.sol";

contract Exchanger is IDHKE {
    uint256 generator;
    string primehex;
    string source;
    address public owner;

    uint256 public version = 0;

    constructor(uint256 _generator, string memory _primehex) 
    {
        generator = _generator;
        primehex = _primehex;
        owner = msg.sender;
    }

    /// @notice -- every user has a unique public key
    mapping (address => string) public publicKeys;

    // every user <> recipient interaction has an individual nonce
    mapping (address => mapping (address => uint256)) public nonces;

    // every user sends a unique encrypted decryption key for each recipient, with a nonce per peer
    mapping (address => mapping (address => mapping(uint256 => DataPayload))) public DataPayloads;
    
    /// @inheritdoc IDHKE
    function updateConstants
    (
        uint256 _generator,
        string memory _primehex,
        string memory _source
    ) 
    external returns (bool) 
    {
        require(msg.sender == owner, "Only the contract owner can update the cryptography constants.");
        
        generator = _generator;
        primehex = _primehex;
        version++;

        emit constantsUpdated(_generator, _primehex, _source, version);
        return true;
    }

    /// @inheritdoc IDHKE
    function registerEncryptedPayload
    (
        string memory _encryptedDecryptionKey,
        address _sender,
        address _recipient,
        string memory _encryptedData
    ) public returns (bool) 
    {
        // require sender is the msg.sender
        require(msg.sender == _sender, "Cant initiate a send for other users.");
        // require public keys for both sender and recipient
        require(bytes(publicKeys[_sender]).length > 0, "Sender must have a registered public key.");
        require(bytes(publicKeys[_recipient]).length > 0, "Recipient must have a registered public key.");

        nonces[_sender][_recipient]++;
        DataPayload memory payload = DataPayload(_encryptedDecryptionKey,_encryptedData);
        DataPayloads[_sender][_recipient][nonces[_sender][_recipient]] = payload;

        emit encryptedPayloadRegistered(_encryptedDecryptionKey, _sender, _recipient, _encryptedData, nonces[_sender][_recipient]);
        return true;
    }

    /// @inheritdoc IDHKE
    function setPublicKey
    (
        string memory _publicKey
    )
    public returns (bool)
    {
        publicKeys[msg.sender] = _publicKey;
        emit publicKeyRegistered(_publicKey, msg.sender);
        return true;
    }

    function changeOwner
    (
        address _newOwner
    )
    public returns (bool)
    {
        require(msg.sender == owner, "Only the contract owner can change the owner.");
        owner = _newOwner;
        emit ownerUpdated(msg.sender, _newOwner);
        return true;
    }

    function getConstants() external view returns (PublicConstants memory)  {
        PublicConstants memory constants;
        constants.generator = generator;
        constants.primehex = primehex;
        constants.source = source;
        return constants;
    }

    function getEncryptedPayload(address _sender, address _recipient, uint256 _nonce) external view returns (DataPayload memory) {
        DataPayload memory payload = DataPayloads[_sender][_recipient][nonces[_sender][_recipient]];
        return payload;
    }

    function getNonce(address _sender, address _recipient) external view returns (uint256) {
        return nonces[_sender][_recipient];
    }

    function getInverseNonce(address _sender, address _recipient) external view returns (uint256) {
        return nonces[_recipient][_sender];
    }

    function getPublicKey(address _user) external view returns (string memory) {
        return publicKeys[_user];
    }

    function getOwner() external view returns (address) {
        return owner;
    }

}