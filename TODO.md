# TODO's

* make the API GUI ready, which means providing useful information on e.g. new messagesm etc...
* think about sub-protocols
* Create a sort of GROUP

## SUB PROTOCOLS
send msg to Entity:
decode entity
create api or load from GUI structure
sendto ...
save api in GUI structure if not exist


The Message Object, should ALWAYS specify a type,
NO type is assumed.

A sends B a mesage:

A's side:
Queue()
Queue(Msg(B, MSG, key=random_private_key, key2=shared_key))


