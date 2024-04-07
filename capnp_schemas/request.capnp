@0xd88ef70c99c403a7;
enum RequestType {
    register @0;
    challenge @1;
    response @2;
    reauth @3;
    status @4;
}

struct Request {
    union {
        noNonce @2 :Void;
        nonceChallenge @0 :Data;
        nonceSolution @1 :Data;
        statusCode @4 :UInt16;
    }
    # Either the nonce challenge is sent to the client, or the solution to the server

    requestType @3 :RequestType;
    # Represents the type of request in the protocol
}