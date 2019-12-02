import Signatures

class Tx:
    inputs = None
    outputs = None
    signatures = None
    reqSignatures = None
    
    def __init__(self):
        self.inputs = []
        self.outputs = []
        self.signatures = []
        self.reqSignatures = []
    
    def add_input(self, from_addr, amount):
        self.inputs.append((from_addr, amount))
    def add_output(self, to_addr, amount):
        self.outputs.append((to_addr, amount))
    def add_req_sign(self, addr):
        self.reqSignatures.append(addr)
    def sign(self, private):
        message = self.__gather()
        newSig = Signatures.sign(message, private)
        self.signatures.append(newSig)
    def is_valid(self):
        total_in = 0
        total_out = 0
        message = self.__gather()
        for addr, amount in self.inputs:
            found = False
            for s in self.signatures:
                if Signatures.verify(message, s, addr):
                    found = True
            if not found:
                return False
            if amount < 0:
                return False
            total_in = total_in + amount
        for addr in self.reqSignatures:
            found = False
            for s in self.signatures:
                if Signatures.verify(message, s, addr):
                    found = True
            if not found:
                return False
        for addr, amount in self.outputs:
            if amount < 0:
                return False
            total_out = total_out + amount
        if total_out > total_in:
            return False
        return True
    
    def __gather(self):
        data = []
        data.append(self.inputs)
        data.append(self.outputs)
        data.append(self.reqSignatures)
        return data
    
if __name__ == '__main__':
    pr1, pu1 = Signatures.generate_keys()
    pr2, pu2 = Signatures.generate_keys()
    pr3, pu3 = Signatures.generate_keys()
    pr4, pu4 = Signatures.generate_keys()
    
    # Successful transactions
    # Test 1 - Simple trasnaction
    Tx1 = Tx()
    Tx1.add_input(pu1, 1)
    Tx1.add_output(pu2, 1)
    Tx1.sign(pr1)
    
    # Test 2 - Two outputs
    Tx2 = Tx()
    Tx2.add_input(pu1, 2)
    Tx2.add_output(pu2, 1)
    Tx2.add_output(pu3, 1)
    Tx2.sign(pr1)

    # Test 3 - Escrow transaction
    Tx3 = Tx()
    Tx3.add_input(pu3, 1.2)
    Tx3.add_output(pu1, 1.1)
    Tx3.add_req_sign(pu4)
    Tx3.sign(pr3)
    Tx3.sign(pr4)

    for t in [Tx1, Tx2, Tx3]:
        if t.is_valid():
            print('Success! Transaction is valid.')
        else:
            print('Fail! Transaction is not valid.')
            

    # Fail transactions
    # Test 4 - Wrong signature
    Tx4 = Tx()
    Tx4.add_input(pu1, 1)
    Tx4.add_output(pu2, 1)
    Tx4.sign(pr2)  # <-- Bad signing
    
    # Test 5 - Escrow transaction not signed by the arbiter
    Tx5 = Tx()
    Tx5.add_input(pu3, 1.2)
    Tx5.add_output(pu1, 1.1)
    Tx5.add_req_sign(pu4)
    Tx5.sign(pr3)

    # Test 6 - Two input addresses but sign only one
    Tx6 = Tx()
    Tx6.add_input(pu3, 1)
    Tx6.add_input(pu4, 0.1)
    Tx6.add_output(pu1, 1.1)
    Tx6.add_req_sign(pu4)
    Tx6.sign(pr3)

    # Test 7 - Outputs amount exceed inputs
    Tx7 = Tx()
    Tx7.add_input(pu4, 1.2)
    Tx7.add_output(pu1, 1)
    Tx7.add_output(pu2, 1)
    Tx7.sign(pr4)

    # Test 8 - Negative amounts
    Tx8 = Tx()
    Tx8.add_input(pu2, -1)
    Tx8.add_output(pu1, -1)
    Tx8.sign(pr2)
    
    # Test 9 - Modified transaction after signing
    Tx9 = Tx()
    Tx9.add_input(pu1, 1)
    Tx9.add_output(pu2, 1)
    Tx9.sign(pr1)
    Tx9.outputs[0] = (pu3, 1)

    for t in [Tx4, Tx5, Tx6, Tx7, Tx8, Tx9]:
        if t.is_valid():
            print('Fail! Transaction is valid.')
        else:
            print('Success! Transaction is not valid.')
            