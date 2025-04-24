from sender.sender import sender_process
from receiver.receiver import receiver_process

if __name__ == "__main__":
    choice = input("Run sender or receiver? (s/r): ").strip().lower()
    if choice == "s":
        sender_process()
    elif choice == "r":
        receiver_process()
    else:
        print("Invalid choice.")
