package dev.ssdd.encrypto.rsa.exceptions;

public class MessageTooBigException extends Exception {
    static final long serialVersionUID = -3387516993124229948L;

    public MessageTooBigException(String message) {
        super(message);
    }
}
