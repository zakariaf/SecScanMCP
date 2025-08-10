"""
YARA test case - Polymorphic/obfuscated code patterns
Demonstrates self-modifying and heavily obfuscated code
"""

import base64
import random
import string

class PolymorphicServer:
    """Server that changes its behavior dynamically"""

    def __init__(self):
        # Multiple layers of obfuscation
        self.layer1 = base64.b64encode(b"exec").decode()
        self.layer2 = "ZXZhbA=="  # 'eval' in base64
        self.layer3 = "\x63\x6f\x6d\x70\x69\x6c\x65"  # 'compile' in hex

        # Character-based obfuscation
        self.cmd = chr(101) + chr(120) + chr(101) + chr(99)  # 'exec'

        # Random variable names (polymorphic behavior)
        self._generate_random_vars()

    def _generate_random_vars(self):
        """Generate random variable names to evade detection"""
        self.var1 = ''.join(random.choices(string.ascii_letters, k=8))
        self.var2 = ''.join(random.choices(string.ascii_letters, k=8))
        self.var3 = ''.join(random.choices(string.ascii_letters, k=8))

    def process_input(self, data):
        """Process input with multiple obfuscation layers"""

        # Pattern 1: Heavily encoded payload
        encoded_payload = base64.b64encode(
            base64.b64encode(
                base64.b64encode(b"malicious_code").decode().encode()
            ).decode().encode()
        ).decode()

        # Pattern 2: Dynamic code construction
        code_parts = [
            "im", "po", "rt", " ", "os", ";",
            "os", ".", "sy", "st", "em", "(", "'", "cmd", "'", ")"
        ]
        dynamic_code = ''.join(code_parts)

        # Pattern 3: Mathematical obfuscation
        obf_values = [105, 109, 112, 111, 114, 116]  # 'import'
        reconstructed = ''.join([chr(x) for x in obf_values])

        # Pattern 4: Self-modifying code simulation
        self.__dict__[self.var1] = eval
        self.__dict__[self.var2] = compile
        self.__dict__[self.var3] = exec

        # This pattern triggers YARA's polymorphic detection
        return f"Processed with {len(encoded_payload)} complexity"

    def mutate(self):
        """Change internal structure (polymorphic behavior)"""
        # Regenerate variable names
        self._generate_random_vars()

        # Shuffle internal methods
        methods = [m for m in dir(self) if not m.startswith('_')]
        random.shuffle(methods)

        # Add decoy methods dynamically
        for i in range(3):
            setattr(self, f'decoy_{i}', lambda x: x)

# Additional obfuscation patterns
def create_obfuscated_function():
    """Create function with heavy obfuscation"""

    # Pattern that YARA detects as polymorphic
    func_str = """
def {func_name}({args}):
    {body}
""".format(
        func_name=''.join([chr(ord('a') + i) for i in range(5)]),
        args=''.join([chr(120), chr(44), chr(121)]),  # 'x,y'
        body=base64.b64encode(b"return x + y").decode()
    )

    # Execute obfuscated code
    namespace = {}
    exec(compile(func_str, '<string>', 'exec'), namespace)

    return namespace

# String obfuscation patterns
obfuscated_strings = [
    "".join([chr(i) for i in [115, 121, 115, 116, 101, 109]]),  # 'system'
    base64.b64encode(b"subprocess").decode(),
    "\\x65\\x78\\x65\\x63\\x75\\x74\\x65",  # 'execute' in hex
    "cHJvY2Vzcw==",  # 'process' in base64
]

# This will trigger YARA's polymorphic code detection
server = PolymorphicServer()
server.mutate()