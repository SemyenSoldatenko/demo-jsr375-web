package ru.soldatenko.demo3;

import javax.ejb.AccessLocalException;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;
import java.util.LinkedHashMap;

@Provider
public class EjbAccessExceptionMapper implements ExceptionMapper<AccessLocalException> {
    @Override
    public Response toResponse(AccessLocalException exception) {
        LinkedHashMap<String, String> error = new LinkedHashMap<>();
        error.put("httpStatus", "401");
        error.put("errorClass", exception.getClass().getName());
        error.put("errorMessage", exception.getMessage());
        LinkedHashMap<String, LinkedHashMap<String, String>> map = new LinkedHashMap<>();
        map.put("error", error);
        return Response.status(401).entity(map).build();
    }
}
