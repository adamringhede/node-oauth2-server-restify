--
-- PostgreSQL database dump
--

SET statement_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SET check_function_bodies = false;
SET client_min_messages = warning;

--
-- Name: plpgsql; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS plpgsql WITH SCHEMA pg_catalog;


--
-- Name: EXTENSION plpgsql; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION plpgsql IS 'PL/pgSQL procedural language';


SET search_path = public, pg_catalog;

SET default_tablespace = '';

SET default_with_oids = false;

--
-- Name: oauth_accessTokens; Type: TABLE; Schema: public; Owner: -; Tablespace:
--

CREATE TABLE oauth_accessTokens (
    accessToken text NOT NULL,
    clientId text NOT NULL,
    userId uuid NOT NULL,
    expires timestamp without time zone NOT NULL
);


--
-- Name: oauthClients; Type: TABLE; Schema: public; Owner: -; Tablespace:
--

CREATE TABLE oauthClients (
    clientId text NOT NULL,
    clientSecret text NOT NULL,
    redirect_uri text NOT NULL
);


--
-- Name: oauth_refreshTokens; Type: TABLE; Schema: public; Owner: -; Tablespace:
--

CREATE TABLE oauth_refreshTokens (
    refreshToken text NOT NULL,
    clientId text NOT NULL,
    userId uuid NOT NULL,
    expires timestamp without time zone NOT NULL
);


--
-- Name: users; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE users (
    id uuid NOT NULL,
    username text NOT NULL,
    password text NOT NULL
);


--
-- Name: oauth_accessTokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace:
--

ALTER TABLE ONLY oauth_accessTokens
    ADD CONSTRAINT oauth_accessTokens_pkey PRIMARY KEY (accessToken);


--
-- Name: oauthClients_pkey; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace:
--

ALTER TABLE ONLY oauthClients
    ADD CONSTRAINT oauthClients_pkey PRIMARY KEY (clientId, clientSecret);


--
-- Name: oauth_refreshTokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace:
--

ALTER TABLE ONLY oauth_refreshTokens
    ADD CONSTRAINT oauth_refreshTokens_pkey PRIMARY KEY (refreshToken);


--
-- Name: users_pkey; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: users_username_password; Type: INDEX; Schema: public; Owner: -; Tablespace: 
--

CREATE INDEX users_username_password ON users USING btree (username, password);


--
-- PostgreSQL database dump complete
--

