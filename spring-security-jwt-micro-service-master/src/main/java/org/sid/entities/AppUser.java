package org.sid.entities;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.Collection;
@Entity

public class AppUser {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(unique = true)
    private String username;
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String password;
    private boolean actived;
    @ManyToMany(fetch = FetchType.EAGER)
    private Collection<AppRole> roles=new ArrayList<>();
    public AppUser(Long id,String username,String password,Boolean actived,Collection<AppRole> roles) {
		this.id=id;
		this.username=username;
		this.password=password;
		this.actived=actived;
		this.roles= roles;
	}
	public AppUser(){
		
	}
	
	 public Long getId() {
			return id;
		}
		public void setId(Long id) {
			this.id = id;
		}
		public String getUsername() {
			return username;
		}
		public void setUsername(String username) {
			this.username = username;
		}
		public String getPassword() {
			return password;
		}
		public void setPassword(String password) {
			this.password = password;
		}
		public Boolean getActived() {
			return actived;
		}
		public void setActived(Boolean actived) {
			this.actived = actived;
		}
		public Collection<AppRole> getRoles() {
			return roles;
		}
		public void setRoles(Collection<AppRole> roles) {
			this.roles = roles;
		}
}
