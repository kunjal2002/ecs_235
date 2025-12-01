package com.example.DnsIds.util;

import org.springframework.stereotype.Component;
import java.util.Random;

@Component
public class Helper {

    private final Random random = new Random();

    public int randomInt(int min, int max) {
        return new Random().nextInt(max - min) + min;
    }

    public int randomPort() {
        return randomInt(1024, 65535);
    }

    public String randomDomain() {
        String[] domains = {"google.com", "facebook.com", "youtube.com", "amazon.com", "twitter.com"};
        return domains[new Random().nextInt(domains.length)];
    }

    public String randomString(int length) {
        String chars = "abcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder sb = new StringBuilder();
        Random r = new Random();
        for (int i = 0; i < length; i++) sb.append(chars.charAt(r.nextInt(chars.length())));
        return sb.toString();
    }

    public int randomSize(int min, int max) {
        return randomInt(min, max);
    }

}

