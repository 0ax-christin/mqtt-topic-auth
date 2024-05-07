// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title IIoT Authentication Ticketing Contract
/// @notice This contract is used to create and retrieve authentication tickets in a secure manner
/// @dev Utilizes OpenZeppelin's ECDSA library for private signature operations.
contract SignatureVerifier {
    using ECDSA for bytes32;

    // Mapping from addresses to authorization status (true if authorized).
    mapping(address => bool) public authorizedAccounts;

    // Mapping from ticket ID to Ticket struct for storing ticket details.
    mapping(uint256 => Ticket) tickets;

    // Event emitted upon verification of a signature, primarily used for testing.
    event VerificationResult(string message);

    // Event emitted when a ticket is retrieved, providing all relevant ticket details.
    event TicketRetrieved(
        uint256 id,
        bytes publicKey,
        bytes signature,
        uint256 expiry,
        bytes seed,
        bytes HMAC
    );

    /// @dev Struct to store details of an IoT authentication ticket.
    struct Ticket {
        uint256 id;
        bytes publicKey;
        bytes signature;
        uint256 expiry;
        bytes seed;
        bytes HMAC;
    }

    /// @notice Constructor to initialize the contract with authorized accounts.
    /// @param _authorizedAccounts Array of addresses that are initially authorized.
    constructor(address[] memory _authorizedAccounts) {
        for (uint256 i = 0; i < _authorizedAccounts.length; i++) {
            authorizedAccounts[_authorizedAccounts[i]] = true;
        }
    }

    /// @notice Modifier to restrict functions to authorized addresses only.
    modifier onlyAuthorized() {
        require(authorizedAccounts[msg.sender], "Not authorized");
        _;
    }

    /// @notice Modifier to validate signatures with provided signed hash, signature, and signer address.
    /// @param signedHash The hash that was signed.
    /// @param signature The signature over the signedHash.
    /// @param signer The address that supposedly signed the hash.
    modifier onlyVerifiedSignature(bytes32 signedHash, bytes memory signature, address signer) {
        require(verifySignature(signedHash, signature, signer), "Invalid signature");
        _;
    }

    /// @notice Verifies a signature by recovering the signer and comparing it to the provided signer address.
    /// @param signedHash Hash of the original data that was signed.
    /// @param signature Digital signature over the signedHash.
    /// @param signer Address claimed to have produced the signature.
    /// @return isSignerValid Returns true if the signature is valid for the signer.
    function verifySignature(bytes32 signedHash, bytes memory signature, address signer) public returns (bool) {
        address recoveredSigner = signedHash.recover(signature);
        bool isSignerValid = recoveredSigner == signer;
        if (isSignerValid) {
            emit VerificationResult("Signature verified successfully.");
        } else {
            emit VerificationResult("Signature verification failed.");
        }
        return isSignerValid;
    }

    /// @notice Registers a new IoT authentication ticket after verifying the sender's signature.
    /// @param id Unique identifier for the ticket.
    /// @param expiry Expiry timestamp of the ticket.
    /// @param publicKey Public key associated with the IoT device.
    /// @param signature Signature proving the authenticity of the ticket.
    /// @param seed Random seed used in cryptographic operations for the ticket.
    /// @param HMAC HMAC of the ticket details for added security.
    /// @param signedHash Hash of the data signed by the server for authentication.
    /// @param _signature Signature over the signedHash by the server.
    /// @param signer Address of the signer (server) to be verified.
    function registerTicket(
        uint256 id,
        uint256 expiry,
        bytes memory publicKey,
        bytes memory signature,
        bytes memory seed,
        bytes memory HMAC,
        bytes32 signedHash,
        bytes memory _signature,
        address signer
    ) public onlyAuthorized onlyVerifiedSignature(signedHash, _signature, signer) {
        Ticket storage ticket = tickets[id];
        ticket.id = id;
        ticket.publicKey = publicKey;
        ticket.signature = signature;
        ticket.expiry = expiry;
        ticket.seed = seed;
        ticket.HMAC = HMAC;
    }

    /// @notice Retrieves and emits the details of an IoT authentication ticket.
    /// @param id Identifier of the ticket to retrieve.
    /// @param signedHash Hash that was signed to authenticate the request.
    /// @param _signature Signature corresponding to the signedHash.
    /// @param signer Address of the signer to verify against the signature.
    function getTicket(
        uint256 id,
        bytes32 signedHash,
        bytes memory _signature,
        address signer
    ) public onlyAuthorized onlyVerifiedSignature(signedHash, _signature, signer) {
        Ticket storage iot_ticket = tickets[id];
        emit TicketRetrieved(
            iot_ticket.id,
            iot_ticket.publicKey,
            iot_ticket.signature,
            iot_ticket.expiry,
            iot_ticket.seed,
            iot_ticket.HMAC
        );
    }
}
