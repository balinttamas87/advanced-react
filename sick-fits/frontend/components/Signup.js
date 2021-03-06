import React, { Component } from "react";
import { Mutation } from "react-apollo";
import gql from "graphql-tag";
import Error from "./ErrorMessage";
import Form from "./styles/Form";
import { CURRENT_USER_QUERY } from "./User";

const SIGNUP_MUTATION = gql`
  mutation SIGNUP_MUTATION(
    $email: String!
    $password: String!
    $name: String!
  ) {
    signup(email: $email, password: $password, name: $name) {
      id
      email
      name
    }
  }
`;
class Signup extends Component {
  state = {
    email: "",
    name: "",
    password: ""
  };
  saveToState = e => {
    this.setState({
      [e.target.name]: e.target.value
    });
  };
  render() {
    return (
      <Mutation
        mutation={SIGNUP_MUTATION}
        variables={this.state}
        refetchQueries={[{ query: CURRENT_USER_QUERY }]}
      >
        {(signup, { loading, error }) => {
          return (
            <Form
              method="post"
              onSubmit={async e => {
                e.preventDefault();
                await signup();
                this.setState({
                  email: "",
                  name: "",
                  password: ""
                });
              }}
            >
              <fieldset disabled={loading} aria-busy={loading}>
                <h2>Sign Up for An Account</h2>
                <Error error={error} />

                <label htmlFor="email">
                  Email
                  <input
                    type="email"
                    name="email"
                    placeholder="email"
                    value={this.state.email}
                    onChange={this.saveToState}
                  />
                </label>

                <label htmlFor="name">
                  Name
                  <input
                    type="text"
                    name="name"
                    placeholder="name"
                    value={this.state.name}
                    onChange={this.saveToState}
                  />
                </label>

                <label htmlFor="password">
                  Password
                  <input
                    type="password"
                    name="password"
                    placeholder="password"
                    value={this.state.password}
                    onChange={this.saveToState}
                  />
                </label>

                <button type="submit">Sign In</button>
              </fieldset>
            </Form>
          );
        }}
      </Mutation>
    );
  }
}

export default Signup;
