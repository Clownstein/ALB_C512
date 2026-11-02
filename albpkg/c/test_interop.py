"""Exercise the real C EVP provider against Python. Requires a built C library."""
import ctypes as c
import os
from pathlib import Path
import shutil
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python"))
from albpkg.identity import (
    _save_legacy_identity,
    generate_identity,
    load_identity,
    save_identity,
)
from albpkg.contacts import Contact, ContactStore, Trust
from albpkg.package import seal_file, open_file


class CContact(c.Structure):
    _fields_ = [("pubid", c.c_ubyte * 3150), ("trust", c.c_int)]


def main():
    dll_dir = os.add_dll_directory(sys.argv[2]) if os.name == "nt" else None
    lib = c.CDLL(str(Path(sys.argv[1]).resolve()))
    lib.alb_last_error.restype = c.c_int
    lib.alb_identity_from_seeds.argtypes = [c.c_char_p, c.c_char_p, c.POINTER(c.c_void_p)]
    lib.alb_identity_free.argtypes = [c.c_void_p]
    lib.alb_export_public_identity.argtypes = [c.c_void_p, c.c_void_p, c.c_size_t]
    lib.alb_import_contact.argtypes = [c.c_char_p, c.c_size_t, c.POINTER(CContact)]
    lib.alb_verify_contact.argtypes = [c.POINTER(CContact), c.c_char_p]
    for name in ("alb_seal_file", "alb_open_file"):
        getattr(lib, name).argtypes = [c.c_void_p, c.POINTER(CContact), c.c_char_p, c.c_char_p, c.c_void_p, c.c_void_p]
    passphrase_type = c.CFUNCTYPE(c.c_int, c.c_void_p, c.c_void_p, c.c_size_t, c.POINTER(c.c_size_t), c.c_int)
    lib.alb_save_identity.argtypes = [c.c_void_p, c.c_char_p, passphrase_type, c.c_void_p, c.c_int]
    lib.alb_load_identity.argtypes = [c.c_char_p, passphrase_type, c.c_void_p, c.POINTER(c.c_void_p)]
    lib.alb_migrate_legacy_identity.argtypes = [
        c.c_char_p,
        c.c_char_p,
        passphrase_type,
        c.c_void_p,
        c.c_int,
        c.POINTER(c.c_void_p),
    ]
    secret = b"correct horse battery staple"
    @passphrase_type
    def provide_passphrase(_user, output, capacity, length, _confirm):
        if capacity < len(secret): return 0
        c.memmove(output, secret, len(secret)); length[0] = len(secret); return 1
    identities = [generate_identity(), generate_identity()]
    handles, contacts = [], []
    try:
        for identity in identities:
            handle = c.c_void_p()
            assert lib.alb_identity_from_seeds(identity.kem_private.private_bytes_raw(), identity.sig_private.private_bytes_raw(), c.byref(handle)) == 0
            handles.append(handle)
            public = c.create_string_buffer(3150)
            assert lib.alb_export_public_identity(handle, public, 3150) == 0
            assert public.raw == identity.public.pubid
            contact = CContact()
            assert lib.alb_import_contact(public.raw, 3150, c.byref(contact)) == 0
            assert contact.trust == 0
            assert lib.alb_verify_contact(c.byref(contact), identity.fingerprint) == 0
            contacts.append(contact)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            c_identity = root / "c-identity.key"
            assert lib.alb_save_identity(handles[0], str(c_identity).encode(), provide_passphrase, None, 0) == 0
            assert load_identity(c_identity, passphrase_provider=lambda _: secret.decode()).fingerprint == identities[0].fingerprint
            py_identity = root / "python-identity.key"
            save_identity(identities[1], py_identity, passphrase_provider=lambda _: secret.decode())
            imported = c.c_void_p()
            assert lib.alb_load_identity(str(py_identity).encode(), provide_passphrase, None, c.byref(imported)) == 0
            imported_public = c.create_string_buffer(3150)
            assert lib.alb_export_public_identity(imported, imported_public, 3150) == 0
            assert imported_public.raw == identities[1].public.pubid
            lib.alb_identity_free(imported)

            # The loader validates the already-open file handle. A copied key
            # inherits ordinary directory permissions and must be rejected.
            insecure_identity = root / "insecure-identity.key"
            shutil.copyfile(c_identity, insecure_identity)
            rejected_identity = c.c_void_p()
            assert lib.alb_load_identity(
                str(insecure_identity).encode(),
                provide_passphrase,
                None,
                c.byref(rejected_identity),
            ) != 0
            assert lib.alb_last_error() == 8  # ALB_ERR_PERMISSION
            assert not rejected_identity.value

            # Canonical object ordering and exact file termination are strict.
            identity_blob = c_identity.read_bytes()
            marker = b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
            second = identity_blob.find(marker, len(b"ALBPKG PRIVATE IDENTITY 1\n") + 1)
            assert second > 0
            swapped_identity = root / "swapped-identity.key"
            swapped_identity.write_bytes(
                identity_blob[:len(b"ALBPKG PRIVATE IDENTITY 1\n")]
                + identity_blob[second:]
                + identity_blob[len(b"ALBPKG PRIVATE IDENTITY 1\n"):second]
            )
            if os.name != "nt":
                swapped_identity.chmod(0o600)
            else:
                # Use the canonical writer to get a private ACL, then replace
                # only its contents without changing its handle permissions.
                assert lib.alb_save_identity(
                    handles[0], str(swapped_identity).encode(), provide_passphrase, None, 1
                ) == 0
                swapped_identity.write_bytes(
                    identity_blob[:len(b"ALBPKG PRIVATE IDENTITY 1\n")]
                    + identity_blob[second:]
                    + identity_blob[len(b"ALBPKG PRIVATE IDENTITY 1\n"):second]
                )
            assert lib.alb_load_identity(
                str(swapped_identity).encode(),
                provide_passphrase,
                None,
                c.byref(rejected_identity),
            ) != 0
            assert not rejected_identity.value

            legacy = root / "legacy-identity.key"
            migrated = root / "c-migrated-identity.key"
            _save_legacy_identity(
                identities[0],
                legacy,
                passphrase_provider=lambda _: secret.decode(),
            )
            legacy_before = legacy.read_bytes()
            alias_parent = root / "migration-alias"
            alias_parent.mkdir()
            same_source_alias = alias_parent / ".." / legacy.name
            rejected_alias = c.c_void_p()
            assert lib.alb_migrate_legacy_identity(
                str(legacy).encode(),
                str(same_source_alias).encode(),
                provide_passphrase,
                None,
                1,
                c.byref(rejected_alias),
            ) != 0
            assert lib.alb_last_error() == 1  # ALB_ERR_ARGUMENT
            assert not rejected_alias.value
            assert legacy.read_bytes() == legacy_before
            migrated_handle = c.c_void_p()
            assert lib.alb_migrate_legacy_identity(
                str(legacy).encode(),
                str(migrated).encode(),
                provide_passphrase,
                None,
                0,
                c.byref(migrated_handle),
            ) == 0
            assert legacy.read_bytes() == legacy_before
            assert load_identity(
                migrated, passphrase_provider=lambda _: secret.decode()
            ).fingerprint == identities[0].fingerprint
            lib.alb_identity_free(migrated_handle)
            print("C/Python encrypted PKCS#8 identity interoperability passed")
            store = ContactStore(root / "contacts")
            store.import_contact("sender", identities[0].public)
            store.verify_contact("sender", identities[0].fingerprint.hex())
            def invoke(name, key, contact, src, dst):
                return getattr(lib, name)(handles[key], c.byref(contacts[contact]), str(src).encode(), str(dst).encode(), None, None)
            for size in (0, 1, 1048575, 1048576, 1048577, 2097152):
                data = os.urandom(size)
                src = root / f"source-{size}"
                src.write_bytes(data)
                cpkg, ppkg = root / f"c-{size}", root / f"python-{size}"
                assert invoke("alb_seal_file", 0, 1, src, cpkg) == 0
                pout = root / f"pout-{size}"
                open_file(recipient=identities[1], contacts=store, package_path=cpkg, output_path=pout)
                assert pout.read_bytes() == data
                seal_file(sender=identities[0], recipient=Contact("recipient", identities[1].public, Trust.VERIFIED), input_path=src, output_path=ppkg)
                cout = root / f"cout-{size}"
                assert invoke("alb_open_file", 1, 0, ppkg, cout) == 0
                assert cout.read_bytes() == data
                assert invoke("alb_open_file", 1, 0, ppkg, cout) != 0
                assert lib.alb_last_error() == 11  # ALB_ERR_EXISTS
                assert cout.read_bytes() == data
                altered = bytearray(ppkg.read_bytes())
                altered[1200] ^= 1
                ppkg.write_bytes(altered)
                rejected = root / f"rejected-{size}"
                assert invoke("alb_open_file", 1, 0, ppkg, rejected) != 0
                assert not rejected.exists()
                contacts[1].trust = 0
                assert invoke("alb_seal_file", 0, 1, src, rejected) != 0
                contacts[1].trust = 2
                assert invoke("alb_seal_file", 0, 1, src, rejected) != 0
                contacts[1].trust = 1
                assert not list(root.glob("*.t"))
                print(f"C/Python interoperability and rejection checks passed: {size} bytes")
            # Signed malformed frames exercise the parser beyond signature rejection.
            import hashlib
            from albpkg.package import signature_message
            valid = cpkg.read_bytes()
            def signed(body):
                signature = identities[0].sig_private.sign(signature_message(hashlib.sha512(body).digest()))
                return body + signature + len(signature).to_bytes(4, "big") + b"ALBPKGSG"
            cases = [valid[:-1], valid + b"extra"]
            for offset in (8, 10, 12, 16, 20, 24, 56, 88, 104, 106, 1194, 1195, 1199):
                body = bytearray(valid[:-3321])
                body[offset] ^= 0x80
                cases.append(signed(body))
            for index, malformed in enumerate(cases):
                bad = root / f"malformed-{index}"
                bad.write_bytes(malformed)
                destination = root / f"malformed-out-{index}"
                assert invoke("alb_open_file", 1, 0, bad, destination) != 0
                assert not destination.exists()
                assert not list(root.glob("*.t"))
            # Cancellation and a destination created during processing must preserve it.
            callback_type = c.CFUNCTYPE(c.c_int, c.c_void_p)
            cancelled = callback_type(lambda _: 1)
            output = root / "cancelled"
            assert lib.alb_seal_file(handles[0], c.byref(contacts[1]), str(src).encode(), str(output).encode(), cancelled, None) != 0
            assert lib.alb_last_error() == 9  # ALB_ERR_CANCELLED
            assert not output.exists()
            raced = root / "raced"
            def create_destination(_):
                if not raced.exists():
                    raced.write_bytes(b"preserve this file")
                return 0
            race_callback = callback_type(create_destination)
            assert lib.alb_seal_file(handles[0], c.byref(contacts[1]), str(src).encode(), str(raced).encode(), race_callback, None) != 0
            assert raced.read_bytes() == b"preserve this file"
            assert not list(root.glob("*.t"))
            print("C signed malformed-frame, cancellation, and publication-race checks passed")
    finally:
        for handle in handles:
            lib.alb_identity_free(handle)
        if dll_dir:
            dll_dir.close()


if __name__ == "__main__":
    main()
