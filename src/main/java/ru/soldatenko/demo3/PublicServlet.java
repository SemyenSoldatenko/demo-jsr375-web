package ru.soldatenko.demo3;

import javax.json.bind.JsonbBuilder;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.security.Principal;
import java.util.LinkedHashMap;
import java.util.stream.Stream;

import static java.util.stream.Collectors.toMap;

@WebServlet(urlPatterns = "/servlet/javax.servlet.http.HttpServlet")
public class PublicServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
        res.setContentType("application/json");
        HttpSession session = req.getSession(false);
        Principal principal = req.getUserPrincipal();

        Demo3Dto dto = Demo3Dto.builder()
                .requestUri(req.getRequestURI())
                .callerDn(principal != null ? principal.getName() : null)
                .sessionId(session != null ? session.getId() : null)
                .groupMembership(Stream.of(
                        "cn=All,ou=Groups,dc=demo3,dc=soldatenko,dc=ru",
                        "cn=cph,ou=Groups,dc=demo3,dc=soldatenko,dc=ru",
                        "cn=sf,ou=Groups,dc=demo3,dc=soldatenko,dc=ru"
                        ).collect(toMap(role -> role, req::isUserInRole, (a, b) -> a, LinkedHashMap::new))
                ).build();

        JsonbBuilder.create().toJson(dto, res.getOutputStream());
    }
}
