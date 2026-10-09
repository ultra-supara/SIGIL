"""Hash every member of an uncompressed tar stream read from stdin.

Nothing is extracted to disk. Member names are untrusted and only emitted as
JSON strings. Usage: zstd -dc file | python3 -I tar_manifest.py OUT.json TAG
"""
import hashlib
import json
import sys
import tarfile


def main() -> None:
    out_path, tag = sys.argv[1], sys.argv[2]
    entries = []
    with tarfile.open(fileobj=sys.stdin.buffer, mode="r|") as tar:
        for member in tar:
            entry = {"name": member.name, "type": member.type.decode(errors="replace"), "mode": oct(member.mode)}
            if member.issym() or member.islnk():
                entry["link"] = member.linkname
            elif member.isfile():
                handle = tar.extractfile(member)
                digest = hashlib.sha256()
                size = 0
                while True:
                    chunk = handle.read(1 << 20)
                    if not chunk:
                        break
                    digest.update(chunk)
                    size += len(chunk)
                entry["size"] = size
                entry["sha256"] = digest.hexdigest()
            entries.append(entry)
    with open(out_path, "w") as out:
        json.dump({"tag": tag, "entries": entries}, out, indent=1, sort_keys=True)


if __name__ == "__main__":
    main()
