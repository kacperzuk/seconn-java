package pl.kacperzuk.libs.seconn;


class Message {
    enum MessageType {
        HelloRequest(0x00),
        HelloResponse(0x01),
        EncryptedData(0x02),
        MAX_MESSAGE_TYPE(0x03);

        private final int id;

        MessageType(int id) {
            this.id = id;
        }

        public byte getValue() {
            return (byte) id;
        }
    }

    MessageType type;
    byte[] raw_payload;
}
