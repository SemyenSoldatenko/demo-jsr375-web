package ru.soldatenko.demo3;

import lombok.Builder;
import lombok.Data;

import javax.json.bind.annotation.JsonbNillable;
import javax.json.bind.annotation.JsonbPropertyOrder;
import java.util.LinkedHashMap;

@Data
@Builder
@JsonbPropertyOrder({"callerDn", "sessionId", "requestUri", "groupMembership"})
@JsonbNillable
public class Demo3Dto {
    private String callerDn;
    private String sessionId;
    private String requestUri;
    private LinkedHashMap<String, Boolean> groupMembership;
}
