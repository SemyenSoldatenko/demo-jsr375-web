package ru.soldatenko.demo3;

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.security.enterprise.AuthenticationStatus;
import javax.security.enterprise.SecurityContext;
import javax.security.enterprise.authentication.mechanism.http.AuthenticationParameters;
import javax.security.enterprise.credential.UsernamePasswordCredential;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import java.util.LinkedHashMap;

import static javax.security.enterprise.AuthenticationStatus.SUCCESS;

@Path("login")
@RequestScoped
public class LoginResource {
    @Inject
    PublicResource publicResource;

    @Inject
    SecurityContext cx;

    @POST
    public Response doLogin(@Context UriInfo uriInfo, @Context HttpServletRequest req,
                            @Context HttpServletResponse res, @FormParam("login") String login,
                            @FormParam("password") String password) {
        AuthenticationParameters parameters = new AuthenticationParameters()
                .credential(new UsernamePasswordCredential(login, password));
        AuthenticationStatus status = cx.authenticate(req, res, parameters);
        if (status == SUCCESS) {
            return publicResource.getPublicResource(uriInfo, req);
        } else {
            LinkedHashMap<String, String> error = new LinkedHashMap<>();
            error.put("httpStatus", "401");
            error.put("message", "Authorization failed.");
            LinkedHashMap<String, LinkedHashMap<String, String>> response = new LinkedHashMap<>();
            response.put("error", error);
            return Response.status(401)
                    .entity(response)
                    .build();
        }
    }
}
