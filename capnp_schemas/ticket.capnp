@0xa95e4927317114f4;

struct Ticket {
    ticketId @0 :Text;
    # A unique ticket ID, generated as a random uuid hex string
    mqttTopic @1 :Text;
    # The devices specific authentication topic where reauthentication takes place
    mqttUsername @2 :Text;
    # The devices username by which it can publish data
    signature @3 :Data;
    # Authentication ticket signed with private key of server
}