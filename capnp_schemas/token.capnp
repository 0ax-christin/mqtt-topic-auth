@0xa95e4927317114f4;

struct Token {
    ticketId @0 :Text;
    # A unique ticket ID, generated as a random uuid hex string
    mqttTopic @1 :Text;
    # The devices specific authentication topic where reauthentication takes place
    mqttUsername @2 :Text;
    # The devices username by which it can publish data
    hmacKey @3 :Data;
    # part of the secret required to generate a valid challenge response
    seed @4 :Data;
    # Used as the base which allows a unique solution per challenge
}

struct SignedToken {
    token @0 :Token;
    signature @1 :Data;
}