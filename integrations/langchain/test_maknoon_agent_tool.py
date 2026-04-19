import unittest
import os
import subprocess
import shutil
import tempfile
import json
from maknoon_agent_tool import (
    generate_maknoon_password,
    generate_maknoon_passphrase,
    get_maknoon_file_info,
    encrypt_maknoon_file,
    decrypt_maknoon_file
)

class TestMaknoonLangChainTools(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Setup a temporary directory for keys and files
        cls.test_dir = tempfile.mkdtemp()
        cls.keys_dir = os.path.join(cls.test_dir, ".maknoon", "keys")
        os.makedirs(cls.keys_dir, exist_ok=True)
        
        # Point environment to our temp home
        os.environ["HOME"] = cls.test_dir
        
        # Build maknoon binary
        cls.binary_path = os.path.join(cls.test_dir, "maknoon")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        cmd_dir = os.path.join(script_dir, "../../cmd/maknoon")
        subprocess.run(["go", "build", "-o", cls.binary_path, cmd_dir], check=True)
        os.environ["MAKNOON_BINARY"] = cls.binary_path

        # Generate a test identity
        subprocess.run([
            cls.binary_path, "keygen", "-o", "test-agent", "--no-password"
        ], env={**os.environ, "MAKNOON_JSON": "1"}, check=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.test_dir, ignore_errors=True)

    def test_password_gen(self):
        res = generate_maknoon_password.invoke({"length": 20})
        self.assertIn("password", res)
        self.assertEqual(len(res["password"]), 20)

    def test_passphrase_gen(self):
        res = generate_maknoon_passphrase.invoke({"words": 3, "separator": "."})
        self.assertIn("passphrase", res)
        self.assertEqual(len(res["passphrase"].split(".")), 3)

    def test_file_lifecycle(self):
        input_file = os.path.join(self.test_dir, "hello.txt")
        with open(input_file, "w") as f:
            f.write("agent-test-payload")
        
        output_file = input_file + ".makn"
        pub_key = os.path.join(self.keys_dir, "test-agent.kem.pub")
        priv_key = os.path.join(self.keys_dir, "test-agent.kem.key")

        # 1. Encrypt
        enc_res = encrypt_maknoon_file.invoke({
            "input_path": input_file,
            "output_path": output_file,
            "public_key_path": pub_key
        })
        self.assertEqual(enc_res.get("status"), "success")

        # 2. Info
        info_res = get_maknoon_file_info.invoke({"file_path": output_file})
        self.assertEqual(info_res.get("type"), "asymmetric")
        self.assertIn("kem_algorithm", info_res)

        # 3. Decrypt
        dec_content = decrypt_maknoon_file.invoke({
            "file_path": output_file,
            "private_key_path": priv_key
        })
        self.assertEqual(dec_content.strip(), "agent-test-payload")

if __name__ == "__main__":
    unittest.main()
