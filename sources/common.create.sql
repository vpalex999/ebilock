--SQL SCRIPT to create database
CREATE CATALOG IT_AA_EHA;

SET CATALOG IT_AA_EHA;

-- settings are in this table, some parameters like admin's can go into this 
CREATE TABLE EHA_SETTING(
	set_name varchar(255) unique not null,
	set_value wvarchar(255)
);

CREATE TABLE EHA_ZONE(
	-- unique zone id
	zone_id integer,
	
	-- zone number 1..36 ??
	zone_num SMALLINT,
	-- object controller
	oc_id integer, 
	-- zone name
	zone_name wvarchar(255),
	
	PRIMARY KEY(zone_id),
	-- link to object controller
	FOREIGN KEY (oc_id) REFERENCES EHA_OBJ_CTRL(oc_id)
);

-- list of railroad's switches
CREATE TABLE EHA_SWITCH(
	-- 
	switch_id integer, 
	-- this name have to be playing in dynamics
	switch_name wvarchar(255),
	
	PRIMARY KEY(switch_id)
);

-- list of phones to notify, dynamics phones
CREATE TABLE EHA_PHONE(
	-- 
	phone_id integer, 
	-- this phone numbe will be used to deliver the message
	phone_number wvarchar(255),
	
	PRIMARY KEY(phone_id)
);

-- link between zones and switches
CREATE TABLE EHA_ZONE_SWITCH(
	zone_id integer,
	switch_id integer
);

-- link between zones and phone
CREATE TABLE EHA_ZONE_PHONE(
	zone_id integer,
	phone_id integer
);

CREATE TABLE EHA_OBJ_CTRL(
	-- controller's id 
	oc_id integer,
	oc_num smallint,
	-- controller's name
	oc_name wvarchar(255),
	
	PRIMARY KEY(oc_id)
);


CREATE TABLE ID_GEN(
	gen_name varchar(255),
	gen_val integer
);

