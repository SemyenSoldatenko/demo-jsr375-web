package ru.soldatenko.demo3;

import javax.annotation.Resource;
import javax.annotation.security.DeclareRoles;
import javax.ejb.SessionContext;
import javax.ejb.Stateless;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import java.security.Principal;
import java.util.LinkedHashMap;
import java.util.stream.Stream;

import static java.util.stream.Collectors.toMap;

@Path("javax.ejb.SessionContext")
@Stateless
@DeclareRoles({
        "cn=All,ou=Groups,dc=demo3,dc=soldatenko,dc=ru",
        "cn=cph,ou=Groups,dc=demo3,dc=soldatenko,dc=ru",
        "cn=sf,ou=Groups,dc=demo3,dc=soldatenko,dc=ru",
        "uid=alice,ou=Users,dc=demo3,dc=soldatenko,dc=ru",
        "uid=bob,ou=Users,dc=demo3,dc=soldatenko,dc=ru"
})
public class PublicEjbSessionContextResource {

    @Resource
    SessionContext cx;

    @GET
    public Response getPublicResource(@Context UriInfo uriInfo, @Context HttpServletRequest req) {
        HttpSession session = req.getSession(false);
        Principal principal = cx.getCallerPrincipal();

        Demo3Dto dto = Demo3Dto.builder()
                .requestUri(uriInfo.getRequestUri().toString())
                .callerDn(principal != null ? principal.getName() : null)
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
