from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
import json

from block import Block


class Node:
    def __init__(self, name, dodocoin, connected_node=None):
        self.previous_block_hash = None
        self.node_name = name
        self.cryptocurrency = dodocoin
        self._chain = []
        self.connected_node = []
        # Problem Statement 4.a
        # Initialize the attribute connected_nodes as a blank list
        self.connected_nodes = []
        self._get_chain()

    def __str__(self):
        return f'Node - {self.node_name} - Chain:\n{self._chain}'

    def _get_chain(self, connected_node=None):
        # Problem Statement 4.b
        # Change the if statement to check for the length of connected_nodes
        if len(self.connected_nodes) == 0:
            if self.cryptocurrency.genesis_block is not None:
                self._chain.append(self.cryptocurrency.genesis_block)
        else:
            self._pull_chain_from_a_node(self.connected_nodes)

    def _pull_chain_from_a_node(self, node):
        self._chain = []
        for chain_block in node._chain:
            self._chain.append(chain_block)

    def connect_with_new_node(self, node, sync_chain=False):

        # Problem Statement 4.c
        # Change the code to check for length and remove the unwanted code
        if len(self.connected_nodes) == 0:
            print("No connected nodes")
            #self.connected_nodes.pop(0)
        self.connected_nodes.append(node)
        if sync_chain is True:
            node_with_longest_chain = self._check_node_with_longest_chain()
            self._pull_chain_from_a_node(node_with_longest_chain)

    def _check_node_with_longest_chain(self):
        node_with_longest_chain = None
        chain_length = 0
        for node in self.connected_nodes:
            if len(node._chain) > chain_length:
                chain_length = len(node._chain)
                node_with_longest_chain = node
        return node_with_longest_chain

    def create_new_block(self):
        # Problem Statement 3.b.iv
        # Pass an argument current version to the block class
        new_block = Block(index=len(self._chain), transactions=self.cryptocurrency.mem_pool,
                          difficulty_level=self.cryptocurrency.difficulty_level,
                          previous_block_hash=self._chain[-1].block_hash, metadata='',
                          current_version=self.cryptocurrency.current_version)

        new_block.generate_hash()
        self._chain.append(new_block)
        self.cryptocurrency.mem_pool = []

        # Problem Statement 4.d
        # Change the code to check for length and remove the unwanted code
        if len(self.connected_nodes) != 0:
            self.validate_block(new_block)
            #self.propagate_new_block_to_connected_nodes(new_block)
        return new_block

    def show_chain(self):
        print(f"Chain of node - {self.node_name}")
        for chain_block in self._chain:
            print(chain_block)

    def add_new_transaction(self, transaction):
        try:
            self._validate_digital_signature(transaction)
        except InvalidSignature as e:
            print("Invalid signature. Cannot add this transaction")
            return

        if self._validate_receiver(transaction):
            transaction_bytes = transaction['transaction_bytes']
            transaction_data = json.loads(transaction_bytes)
            self.cryptocurrency.mem_pool.append(transaction_data)

    def _validate_digital_signature(self, transaction):
        sender_public_key = self.cryptocurrency.wallets[transaction['sender']]
        signature = transaction['signature']
        transaction_bytes = transaction['transaction_bytes']
        sender_public_key.verify(signature, transaction_bytes,
                                 padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                                 hashes.SHA256())

    def _validate_receiver(self, transaction):
        transaction_bytes = transaction['transaction_bytes']
        transaction_data = json.loads(transaction_bytes)
        # print(transaction_data)
        if transaction_data['receiver'] in self.cryptocurrency.wallets:
            return True
        return False

    def propagate_new_block_to_connected_nodes(self, new_block):
        for connected_node in self.connected_nodes:
            connected_node.add_new_block(new_block)

    def add_new_block(self, node):
        self._chain.append(node)

    def show_connected_nodes(self):
        # Problem Statement 4.d
        # Change the code to check for length and remove the unwanted code
        if len(self.connected_nodes) != 0:
            print(f"{self.node_name} is connected with - ", end="")
            for _node in self.connected_nodes:
                print(_node.node_name, end=", ")
            print()

    # Problem Statement 2.a
    # Function to validate a block before it is propagated through the chain
    # Compare the hash of the last block of this chain against the previous_hash of the new block
    def validate_block(self, new_block):
        # Fetch the hash value of last block in the chain
        Curr_block_hash = self._chain[-1].block_hash
        # new_block_hash = Block.block_hash(new_block)
        print(Curr_block_hash)
        # print(new_block_hash)
        # Call function get_previous_hash to get the previous_hash_value
        previous_block_hash = new_block.get_previous_hash()
        print(previous_block_hash)
        # Compare hashes, if both the hashes match propagate the new block to chain
        if Curr_block_hash == previous_block_hash:
            self.propagate_new_block_to_connected_nodes(new_block)

        # pass

if __name__ == "__main__":
    from blockchain import DodoCoin
    from wallet import Wallet

    dodo = DodoCoin()
    node_1 = Node("Node_1", dodo)

    sunil_wallet = Wallet('Sunil', node_1)
    harsh_wallet = Wallet('Harsh', node_1)
    dodo.register_wallet(sunil_wallet.user, sunil_wallet.public_key)
    dodo.register_wallet(harsh_wallet.user, harsh_wallet.public_key)

    sunil_wallet.initiate_transaction("Harsh", 50)
    sunil_wallet.initiate_transaction("Harsh", 20)

    node_1.create_new_block()
    node_1.show_chain()

    node_2 = Node("Node_2", dodo, node_1)
    node_2.show_chain()

    dodo.update_difficulty_level(6)

    harsh_wallet.initiate_transaction("Sunil", 50)
    harsh_wallet.initiate_transaction("Sunil", 20)

    node_1.connect_with_new_node(node_2)
    node_1.create_new_block()
    node_1.show_chain()
    node_2.show_chain()
