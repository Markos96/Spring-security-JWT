package com.markos96.springbootsecurity.jwt;

import com.markos96.springbootsecurity.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private JwtService jwtService;

    private UserDetailsService userDetailsService;

    // realiza los filtros para el token
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        final String token = getTokenFromRequest(request);
        final String username;

        if(token == null){
            filterChain.doFilter(request,response);
            return;
        }

        username = jwtService.getUsernameFromToken(token);

        // Busco el username en el SecurityContextHolder
        if(username != null && SecurityContextHolder.getContext().getAuthentication() == null){

            // Si no lo encuentra en el contexto, voy a buscar a la base con el UserDetails
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            if(jwtService.isTokenValid(token, userDetails)){
                // Actualizo el SecurityContextHolder
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails,
                        null,
                        userDetails.getAuthorities());

                // Seteo el details
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Establezco la request dentro del Security Context Holder
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }

        }

        filterChain.doFilter(request, response);
    }

    // Nos devuelve el token, el cual obtenemos del encabezado del request
    private String getTokenFromRequest(HttpServletRequest request) {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if(StringUtils.hasText(authHeader) && authHeader.startsWith("Bearer ")){
            return authHeader.substring(7);
        }
        return null;
    }

    @Autowired
    public void setJwtService(JwtService jwtService) {this.jwtService = jwtService;}

    @Autowired
    public void setUserDetailsService(UserDetailsService userDetailsService) {this.userDetailsService = userDetailsService;}
}
