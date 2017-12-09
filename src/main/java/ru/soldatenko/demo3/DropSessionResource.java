package ru.soldatenko.demo3;

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

@Path("drop_session")
@RequestScoped
public class DropSessionResource {
    @Inject
    PublicResource publicResource;

    @POST
    public Response doDropSession(@Context UriInfo uriInfo, @Context HttpServletRequest req) {
        req.getSession(true)
                .invalidate();
        return publicResource.getPublicResource(uriInfo, req);
    }
}
