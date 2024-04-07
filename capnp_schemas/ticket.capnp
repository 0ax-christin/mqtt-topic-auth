 @0xa6ca89c51e88496e;

struct Ticket {
       ticketId @0 :Text;
       deviceId @1 :Text;
       publicKey @2 :Data;
       expiry @3 : Int32;
       seed @4 :Data;
       hmacKey @5 :Data;
}

struct SignedTicket {
       ticket @0 :Ticket;
       signature @1 :Data;
}