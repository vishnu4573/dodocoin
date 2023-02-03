from blockchain import DodoCoin
from wallet import Wallet
from node import Node

dodo = DodoCoin()

peter_wallet = Wallet('Peter')
tony_wallet = Wallet('Tony')
strange_wallet = Wallet('Strange')
bruce_wallet = Wallet('Bruce')
steve_wallet = Wallet('Steve')
carol_wallet = Wallet('Carol')
scarlet_wallet = Wallet('Scarlet')
# nebula_wallet = Wallet('Nebula')
# natasha_wallet = Wallet("Natasha")
# shuri_wallet = Wallet('Shuri')

# Register each wallet with Blockchain
dodo.register_wallet(peter_wallet.user, peter_wallet.public_key)
dodo.register_wallet(tony_wallet.user, tony_wallet.public_key)
dodo.register_wallet(strange_wallet.user, strange_wallet.public_key)
dodo.register_wallet(bruce_wallet.user, bruce_wallet.public_key)
dodo.register_wallet(steve_wallet.user, steve_wallet.public_key)
dodo.register_wallet(carol_wallet.user, carol_wallet.public_key)
dodo.register_wallet(scarlet_wallet.user, scarlet_wallet.public_key)
# dodo_chain.register_wallet(nebula_wallet.user, nebula_wallet.public_key)
# dodo_chain.register_wallet(natasha_wallet.user, natasha_wallet.public_key)
# dodo_chain.register_wallet(shuri_wallet.user, shuri_wallet.public_key)

node_1 = Node("Node-1", dodo)
# node_2 = Node("Node-2", dodo)

print(node_1)
# print(node_2)

# Show list of registered wallets.
# print("\nList of registered wallets.")
# dodo.list_wallets()
#
trans = peter_wallet.initiate_transaction(tony_wallet.user, 20)
# node_1.add_new_transaction(transaction)
# print("\nList of pending transactions.")
dodo.list_pending_transactions()
node_1.create_new_block()
print("**********************Node_1 Chain*************************")
node_1.show_chain()
print("***********************************************")
node_2 = Node("Node-2", dodo)
print("*********************Node_2 Chain**************************")
print(node_2)
print("***********************************************")


peter_wallet.initiate_transaction(bruce_wallet.user, 25)
# node_1.add_new_transaction(transaction)
bruce_wallet.initiate_transaction(peter_wallet.user, 50)
# node_1.add_new_transaction(transaction)
tony_wallet.initiate_transaction(bruce_wallet.user, 50)
# node_1.add_new_transaction(transaction)
node_1.create_new_block()
#
# transaction = scarlet_wallet.initiate_transaction(peter_wallet.user, 25)
# node_1.add_new_transaction(transaction)
# transaction = carol_wallet.initiate_transaction(steve_wallet.user, 50)
# node_1.add_new_transaction(transaction)
# transaction = steve_wallet.initiate_transaction(bruce_wallet.user, 50)
# node_1.add_new_transaction(transaction)
#
# node_1.create_new_block()
# print("\nPrinting blockchain.")
print("**********************Node_1 Chain*************************")
print(node_1)
print("***********************************************")
node_3 = Node("Node-3", dodo, node_1)
print("**********************Node_3 Chain*************************")
print(node_3)
print("***********************************************")
node_2.connect_with_new_node(node_1, True)
print("**********************Node_2 Chain*************************")
print(node_2)
print("***********************************************")
node_1.show_connected_nodes()
node_2.show_connected_nodes()
node_3.show_connected_nodes()


