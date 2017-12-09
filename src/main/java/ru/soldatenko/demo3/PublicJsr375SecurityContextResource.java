package ru.soldatenko.demo3;

import ru.soldatenko.demo3.auth.Demo3Principal;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import java.util.LinkedHashMap;
import java.util.Optional;
import java.util.stream.Stream;

import static java.util.stream.Collectors.toMap;


@Path("javax.security.enterprise.SecurityContext")
public class PublicJsr375SecurityContextResource {

    @Inject
    javax.security.enterprise.SecurityContext cx;

    @GET
    public Response getPublicResource(@Context UriInfo uriInfo, @Context HttpServletRequest req) {
        HttpSession session = req.getSession(false);
        Optional<Demo3Principal> principal = cx.getPrincipalsByType(Demo3Principal.class)
                .stream()
                .findFirst();

        Demo3Dto dto = Demo3Dto.builder()
                .requestUri(uriInfo.getRequestUri().toString())
                .callerDn(principal.isPresent() ? principal.get().getName() : null)
                .sessionId(session != null ? session.getId() : null)
                .groupMembership(Stream.of(
                        "cn=All,ou=Groups,dc=demo3,dc=soldatenko,dc=ru",
                        "cn=cph,ou=Groups,dc=demo3,dc=soldatenko,dc=ru",
                        "cn=sf,ou=Groups,dc=demo3,dc=soldatenko,dc=ru"
                        ).collect(toMap(role -> role, cx::isCallerInRole, (a, b) -> a, LinkedHashMap::new))
                ).build();

        return Response.ok(dto)
                .build();
    }
}
