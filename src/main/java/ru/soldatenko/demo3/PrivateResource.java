package ru.soldatenko.demo3;

import javax.annotation.security.RolesAllowed;
import javax.ejb.Stateless;
import javax.inject.Inject;
import javax.inject.Provider;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

@Path("private")
@Stateless
public class PrivateResource {

    @Inject
    Provider<PublicResource> publicResource;

    @GET
    @Path("alice")
    @RolesAllowed("uid=alice,ou=Users,dc=demo3,dc=soldatenko,dc=ru")
    public Response getAliceResource(@Context UriInfo uriInfo, @Context HttpServletRequest req) {
        return publicResource.get().getPublicResource(uriInfo, req);
    }

    @GET
    @Path("bob")
    @RolesAllowed("uid=bob,ou=Users,dc=demo3,dc=soldatenko,dc=ru")
    public Response getBobResource(@Context UriInfo uriInfo, @Context HttpServletRequest req) {
        return publicResource.get().getPublicResource(uriInfo, req);
    }
}
