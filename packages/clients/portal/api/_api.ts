export type HeadersType = {
  [key: string]: string;
};

class API {
  public url: string;

  constructor() {
    this.url = process.env.API_URL;
  }

  async request(
    path,
    { body = null, method = 'GET', token = null } = {
      body: null,
      method: 'GET',
      token: null,
    },
  ) {
    const headers: HeadersType = {
      'Access-Control-Allow-Origin': '*',
      'Content-Type': 'application/json',
      'accept-encoding': 'gzip, deflate, br',
    };
    const referrerPolicy = 'origin';

    if (token) headers.Authorization = `Portal ${token}`;

    try {
      const response = await global.fetch(`${this.url}${path}`, {
        body: body ? JSON.stringify(body) : null,
        headers,
        method,
        referrerPolicy,
      });

      const data = await response.json();

      return { status: response.status, data };
    } catch (error) {
      console.log(error.message);
      return error;
    }
  }
}

export default API;
