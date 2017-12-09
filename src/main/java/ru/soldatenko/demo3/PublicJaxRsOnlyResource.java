package ru.soldatenko.demo3;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;
import javax.ws.rs.core.UriInfo;
import java.security.Principal;
import java.util.LinkedHashMap;
import java.util.stream.Stream;

import static java.util.stream.Collectors.toMap;

@Path("javax.ws.rs.core.SecurityContext")
public class PublicJaxRsOnlyResource {

    @GET
    public Response getPublicResource(@Context SecurityContext cx, @Context UriInfo uriInfo, @Context HttpServletRequest req) {
        HttpSession session = req.getSession(false);
        Principal principal = cx.getUserPrincipal();

        Demo3Dto dto = Demo3Dto.builder()
                .requestUri(uriInfo.getRequestUri().toString())
                .callerDn(principal != null ? principal.getName() : null)
                .sessionId(session != null ? session.getId() : null)
                .groupMembership(Stream.of(
                        "cn=All,ou=Groups,dc=demo3,dc=soldatenko,dc=ru",
                        "cn=cph,ou=Groups,dc=demo3,dc=soldatenko,dc=ru",
                        "cn=sf,ou=Groups,dc=demo3,dc=soldatenko,dc=ru"
                        ).collect(toMap(role -> role, cx::isUserInRole, (a, b) -> a, LinkedHashMap::new))
                ).build();
        return Response.ok(dto)
                .build();
    }
}
