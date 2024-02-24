import capnp

capnp.remove_import_hook()
ticket_capnp = capnp.load('../capnp_schemas/ticket.capnp')


ticket = ticket_capnp.Ticket