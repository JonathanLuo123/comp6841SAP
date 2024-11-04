import crypto from 'crypto';
import readline from 'readline';
import EventEmitter from 'events';

// Event emitter setup for message handling
class ChatChannel extends EventEmitter {}
const chatChannel = new ChatChannel();

// A user can send or receive a message
class User {
    constructor(username) {
        this.username = username;
        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
        });
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.receiveMessages = new Set();
    }

    // This function sends a message to the receiver 
    // Encrypt, sign, and dispatch a message
    sendMessage(receiver, text) {
        const messageBuffer = Buffer.from(text, 'utf8');

        // Create a unique salt for the message
        const salt = crypto.randomBytes(16);
        const saltedMessage = Buffer.concat([salt, messageBuffer]);

        // Generate a signature using the sender's private key
        const signature = crypto.sign('sha256', saltedMessage, {
            key: this.privateKey,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            saltLength: 16,
        });

        // Generate a new ephemeral key pair for this message
        const { publicKey: ephemeralPublicKey, privateKey: ephemeralPrivateKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
        });

        // Encrypt the salted message with the ephemeral public key
        const encryptedBuffer = crypto.publicEncrypt(
            {
                key: ephemeralPublicKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256',
            },
            saltedMessage
        );

        // Generate a random UUID for the message
        const messageId = crypto.randomUUID();

        // Emit event for the receiver with encrypted message and signature, and ephemeral public key
        chatChannel.emit('message', {
            origin: this,
            destination: receiver,
            encryptedBuffer,
            signature,
            messageId,
            ephemeralPublicKey,
            ephemeralPrivateKey
        });
    }

    // Receive, decrypt, and verify incoming messages
    receiveMessage(encryptedBuffer, signature, sender, messageId, ephemeralPrivateKey) {
        let decryptedBuffer, isVerified;
        try {
            // Check if the message has already been sent
            if (this.receiveMessages.has(messageId)) {
                console.error("Duplicate message received");
                return;
            }

            // Attempt to decrypt the message using the ephemeral private key
            decryptedBuffer = crypto.privateDecrypt(
                {
                    key: ephemeralPrivateKey,
                    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                    oaepHash: 'sha256',
                },
                encryptedBuffer
            );

            // Separate the original message from the salt
            const originalMessage = decryptedBuffer.slice(16); // Assuming salt length is 16

            // Verify the signature
            isVerified = crypto.verify(
                'sha256',
                decryptedBuffer,
                {
                    key: sender.publicKey,
                    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                    saltLength: 16,
                },
                signature
            );

            if (!isVerified) {
                throw new Error("Signature verification failed.");
            }

            console.log(`\n${this.username} received: ${originalMessage.toString('utf8')}`);

        } catch (error) {
            console.error(`\n${this.username} received an unreadable message.`);
        }
    }
}

// Setup readline for interaction in terminal
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
});

// Wife and husband as user 
const wife = new User("Wife");
const husband = new User("Husband");

// Event listener for message exchange
// Replicates transmission of meta Data
chatChannel.on('message', ({ origin, destination, encryptedBuffer, signature, messageId, ephemeralPrivateKey }) => {
    destination.receiveMessage(encryptedBuffer, signature, origin, messageId, ephemeralPrivateKey); // Send the origin back to the user
    promptForInput(origin); // Prompt the original sender for the next message
});

// Prompt user to enter a message
function promptForInput(user) {
    rl.question(`${user.username}, enter message: `, (text) => {
        const recipient = user === wife ? husband : wife;
        user.sendMessage(recipient, text);
    });
}

// Start simulation
console.log("Starting secure chat simulation...");
promptForInput(wife);
