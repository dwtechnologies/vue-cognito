import { Config, CognitoIdentityCredentials } from 'aws-sdk/global'
import { CognitoUserPool, CognitoUser, AuthenticationDetails, CognitoUserAttribute } from 'amazon-cognito-identity-js'

export default class VueCognito {
  constructor (options) {
    this.apps = []
    this.options = options
    this.userSession = null
    this.userPool = new CognitoUserPool({
      UserPoolId: options.UserPoolId,
      ClientId: options.ClientId
    })
    Config.region = options.region
    Config.credentials = new CognitoIdentityCredentials({
      IdentityPoolId: options.IdentityPoolId
    })
  }

  isAuthenticated () {
    return new Promise((resolve, reject) => {
      const cognitoUser = this.getCurrentUser()

      if (cognitoUser != null) {
        cognitoUser.getSession((err, session) => {
          if (err) return reject(err)
          return resolve(true)
        })
      }

      return resolve(false)
    })
  }

  register (username, email, password) {
    return new Promise((resolve, reject) => {
      const attributes = [
        new CognitoUserAttribute({
          Name: 'email',
          Value: email
        })
      ]

      this.userPool.signUp(username, password, attributes, null, (err, result) => {
        if (err) return reject(err)
        return resolve(result)
      })
    })
  }

  confirmRegistration (username, code) {
    return new Promise((resolve, reject) => {
      const cognitoUser = new CognitoUser({
        Username: username,
        Pool: this.userPool
      })

      cognitoUser.confirmRegistration(code, true, (err, result) => {
        if (err) return reject(err)
        return resolve(result)
      })
    })
  }

  completeNewPassword (newPassword, data) {
    return new Promise((resolve, reject) => {
      const cognitoUser = new CognitoUser({
        Username: data.attributes.username,
        Pool: new CognitoUserPool({
          UserPoolId: this.options.UserPoolId,
          ClientId: this.options.ClientId
        })
      })

      cognitoUser.Session = data.session
      delete data.attributes.email
      delete data.attributes.username

      cognitoUser.completeNewPasswordChallenge(newPassword, data.attributes, {
        onSuccess: result => {
          return resolve(result)
        },
        onFailure: err => {
          return reject(err)
        }
      })
    })
  }

  resendCode (username, code) {
    return new Promise((resolve, reject) => {
      const cognitoUser = new CognitoUser({
        Username: username,
        Pool: this.userPool
      })

      cognitoUser.resendConfirmationCode((err, result) => {
        if (err) return reject(err)
        return resolve(result)
      })
    })
  }

  login (username, password) {
    return new Promise((resolve, reject) => {
      const authenticationDetails = new AuthenticationDetails({
        Username: username,
        Password: password
      })

      const cognitoUser = new CognitoUser({
        Username: username,
        Pool: this.userPool
      })

      cognitoUser.authenticateUser(authenticationDetails, {
        onSuccess: result => {
          let logins = {}
          logins['cognito-idp.' + this.options.region + '.amazonaws.com/' + this.options.UserPoolId] = result.getIdToken().getJwtToken()

          Config.credentials = new CognitoIdentityCredentials({
            IdentityPoolId: this.options.UserPoolId,
            Logins: logins
          })
          this.onChange(true)
          return resolve({newPasswordRequired: false, ...result})
        },
        onFailure: err => {
          return reject(err)
        },
        newPasswordRequired: (userAttributes, requiredAttributes) => {
          userAttributes.username = cognitoUser.username
          delete userAttributes.email_verified
          return resolve({newPasswordRequired: true, attributes: userAttributes, session: cognitoUser.Session})
        }
      })
    })
  }

  logout () {
    this.getCurrentUser().signOut()
    this.onChange(false)
  }

  getIdToken () {
    return new Promise((resolve, reject) => {
      if (this.userPool.getCurrentUser() == null) return reject(new Error('No user is currently logged in.'))

      this.userPool.getCurrentUser().getSession((err, session) => {
        if (err) return reject(err)
        if (session.isValid()) return resolve(session.getIdToken().getJwtToken())
        return reject(new Error('Session is invalid'))
      })
    })
  }

  getCurrentUser () {
    return this.userPool.getCurrentUser()
  }

  init (app) {
    this.apps.push(app)
  }

  onChange () {}
}

VueCognito.install = (Vue, options) => {
  Object.defineProperty(Vue.prototype, '$cognito', {
    get () { return this.$root._vueCognito }
  })

  Vue.mixin({
    beforeCreate () {
      if (this.$options.cognito) {
        this._vueCognito = this.$options.cognito
        this._vueCognito.init(this)
      }
    }
  })
}
