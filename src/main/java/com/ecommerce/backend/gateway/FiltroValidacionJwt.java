package com.ecommerce.backend.gateway;

import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

@Component
public class FiltroValidacionJwt implements GlobalFilter {
	
	@Value("${url.seguridad}")
	private String urlSeguridad;
	
	@Autowired
	private WebClient.Builder webClientBuilder;
	
	
	public final List<String> RUTAS_PUBLICAS = List.of(
			"/seguridad/login",
			"/seguridad/registro",
			"/seguridad/cambiar-contrasena",
			"/chat-websocket/info"
	);

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
		
		String path = exchange.getRequest().getURI().getPath();
		
		if(RUTAS_PUBLICAS.contains(path)) {
			return chain.filter(exchange);
		}
		
		HttpHeaders cabeceras = exchange.getRequest().getHeaders();
		String cabeceraAutorizacion = cabeceras.getFirst(HttpHeaders.AUTHORIZATION);
		
		if(cabeceraAutorizacion == null || !cabeceraAutorizacion.startsWith("Bearer ")) {
			exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
			return exchange.getResponse().setComplete();
		}
		
		return webClientBuilder.build()
								.post()
								.uri(this.urlSeguridad+"/seguridad/validar-token")
								.header(HttpHeaders.AUTHORIZATION, cabeceraAutorizacion)
								.retrieve()
								.bodyToMono(Map.class)
								.flatMap(respuesta -> {
									String idUsuario = (String) respuesta.get("id");
									ServerHttpRequest requestModificado = exchange.getRequest()
																					.mutate()
																					.header("X-User-ID", idUsuario)
																					.build();
									return chain.filter(exchange.mutate().request(requestModificado).build());
								})
								.onErrorResume(error -> {
									exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
									return exchange.getResponse().setComplete();
								});
								
	}
		
	

}
