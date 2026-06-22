package com.ironhack.simple_auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import jakarta.servlet.http.Cookie;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@AutoConfigureMockMvc
@SpringBootTest
class SimpleAuthApplicationTests {

	@Autowired
	private MockMvc mockMvc;

	@Test
	void contextLoads() {
	}

	@Test
	void loginSendsHttpOnlyTokenCookieAndNoTokenInBody() throws Exception {
		MvcResult result = login();

		Cookie tokenCookie = result.getResponse().getCookie("token");
		assertThat(tokenCookie).isNotNull();
		assertThat(tokenCookie.isHttpOnly()).isTrue();
		assertThat(tokenCookie.getSecure()).isFalse();
		assertThat(tokenCookie.getPath()).isEqualTo("/");
		assertThat(tokenCookie.getValue()).isNotBlank();

		mockMvc.perform(post("/api/login")
						.contentType(MediaType.APPLICATION_JSON)
						.content("""
								{
								  "email": "demo@ironhack.com",
								  "password": "password"
								}
								"""))
				.andExpect(status().isOk())
				.andExpect(cookie().exists("token"))
				.andExpect(jsonPath("$.email").value("demo@ironhack.com"))
				.andExpect(jsonPath("$.token").doesNotExist());
	}

	@Test
	void protectedRouteReadsTokenFromCookie() throws Exception {
		Cookie tokenCookie = login().getResponse().getCookie("token");

		mockMvc.perform(get("/api/me").cookie(tokenCookie))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.email").value("demo@ironhack.com"));
	}

	@Test
	void logoutClearsTokenCookieAndProtectedRouteFailsWithoutIt() throws Exception {
		Cookie tokenCookie = login().getResponse().getCookie("token");

		MvcResult logoutResult = mockMvc.perform(post("/api/logout").cookie(tokenCookie))
				.andExpect(status().isOk())
				.andExpect(cookie().maxAge("token", 0))
				.andReturn();

		Cookie clearedCookie = logoutResult.getResponse().getCookie("token");
		assertThat(clearedCookie).isNotNull();
		assertThat(clearedCookie.isHttpOnly()).isTrue();
		assertThat(clearedCookie.getPath()).isEqualTo("/");

		mockMvc.perform(get("/api/me").cookie(clearedCookie))
				.andExpect(status().isForbidden());
	}

	private MvcResult login() throws Exception {
		return mockMvc.perform(post("/api/login")
						.contentType(MediaType.APPLICATION_JSON)
						.content("""
								{
								  "email": "demo@ironhack.com",
								  "password": "password"
								}
								"""))
				.andExpect(status().isOk())
				.andReturn();
	}
}
