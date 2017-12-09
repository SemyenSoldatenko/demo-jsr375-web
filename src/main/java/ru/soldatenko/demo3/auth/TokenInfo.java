package ru.soldatenko.demo3.auth;

import lombok.Builder;
import lombok.Data;

import javax.json.bind.annotation.JsonbPropertyOrder;
import java.time.LocalDateTime;

@Data
@Builder
@JsonbPropertyOrder({"accessToken", "refreshToken", "expire", "userDn"})
public class TokenInfo {
    private String accessToken;
    private String refreshToken;
    private LocalDateTime expire;
    private String userDn;

    public TokenInfo() {
    }

    public TokenInfo(String accessToken, String refreshToken, LocalDateTime expire, String userDn) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.expire = expire;
        this.userDn = userDn;
    }
}
