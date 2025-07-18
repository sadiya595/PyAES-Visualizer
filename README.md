# AES Encryption and Decryption Tool

A user-friendly desktop application built with Python and Tkinter to demonstrate the Advanced Encryption Standard (AES) algorithm. This tool allows users to encrypt plaintext messages of any length and decrypt the resulting ciphertext back to the original message.

<img width="598" height="704" alt="aes_ss" src="https://github.com/user-attachments/assets/33833d2c-595c-41ef-bb1d-dc1337a78975" />

### Key Features

*   **Secure Encryption:** Implements the core logic of the AES-128 algorithm.
*   **Intuitive UI:** A clean, dark-themed graphical user interface built with Tkinter for a professional look and feel.
*   **Handles Any Message Length:** Automatically applies PKCS#7 padding to encrypt messages of any size, not just 16-byte blocks.
*   **User-Friendly Workflow:** A clear, three-step process for entering plaintext, encrypting, and decrypting.


### Technologies Used

*   **Language:** Python
*   **GUI Library:** Tkinter
*   **Core Algorithm:** A custom implementation of the AES symmetric-key algorithm.


### How to Run This Project

1.  Make sure you have Python installed on your system.
2.  Clone or download this repository to your local machine.
3.  Ensure both `aes.py` and `aes_gui.py` are in the same directory.
4.  Navigate to the project directory in your terminal and run the following command:

    ```
    python aes_gui.py
    ```
5.  The application window will launch.

---

### **Disclaimer**

⚠️ This project was created for educational purposes to demonstrate the AES algorithm's functionality. It uses placeholder values for core cryptographic components like the S-box and key expansion. **It is not cryptographically secure and should not be used to protect real-world, sensitive data.**
