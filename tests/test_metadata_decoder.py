"""Public cbor2 decoder regression tests, especially suffix preservation."""
import unittest
import cbor2
from ethutils import metadata


class DecoderTests(unittest.TestCase):
    def test_decode_consumes_exactly_one_item(self):
        for value in ({'solc': b'\x00\x08\x1e'}, {'ipfs': b'x'*8192}):
            encoded=cbor2.dumps(value)
            suffix=b'\x00\x35\x60\xff'
            self.assertEqual(metadata.decode_cbor(encoded+suffix),(value,suffix))

    def test_metadata_length_and_following_code(self):
        obj={'solc':b'\x00\x08\x1e'}
        encoded=cbor2.dumps(obj)
        code=b'\x60\x00'+encoded+len(encoded).to_bytes(2,'big')+b'\x00'
        self.assertEqual(metadata.extract_metadata(code),[(2,len(encoded)+2,obj)])

    def test_metadata_requires_complete_length_suffix(self):
        encoded = bytes.fromhex('a164736f6c6340')  # {'solc': b''}, seven bytes
        for prefix in (b'', b'\x60\x00'):
            for suffix in (b'', b'\x07'):
                with self.subTest(prefix=prefix.hex(), suffix=suffix.hex()):
                    # A lone 0x07 matches the CBOR size but is not a two-byte suffix.
                    code = prefix + encoded + suffix
                    self.assertEqual(metadata.extract_metadata(code), [])
                    self.assertEqual(metadata.zero_metadata(code), code)
            code = prefix + encoded + b'\x00\x07'
            with self.subTest(prefix=prefix.hex(), suffix='0007'):
                self.assertEqual(metadata.extract_metadata(code),
                                 [(len(prefix), 9, {'solc': b''})])
                self.assertEqual(metadata.zero_metadata(code), prefix + b'\x00' * 9)

    def test_repeated_malformed_decodes_do_not_poison_decoder(self):
        for _ in range(2000):
            for code in (b'\xa1',b'\xa1\x61x',b'\xa1\x7f\x01',b'\xa1\xff'):
                with self.assertRaises(cbor2.CBORDecodeError):metadata.decode_cbor(code)
        self.assertEqual(metadata.decode_cbor(b'\xa0\x00'),({},b'\x00'))


if __name__=='__main__':unittest.main()
