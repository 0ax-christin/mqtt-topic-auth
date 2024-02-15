@0xa95e4927317114f4;

struct Ticket {
    ticketId @0 :Text;
    # A unique ticket ID
    mqttTopic @1 :Text;
    # The devices specific authentication topic where reauthentication takes place
    mqttUsername @2 :Text;
    # The devices username by which it can publish data
    deviceId @3 :Text;
    # Represented by a hash of the public key
    signature @4 :Data;
    # Authentication ticket signed with private key of server
}