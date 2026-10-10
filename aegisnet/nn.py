"""Tiny neural-network engine written from scratch in NumPy: forward pass, backprop, Adam optimiser.
No TensorFlow / PyTorch needed -> runs on any laptop, Raspberry Pi or free cloud VM (Edge AI)."""
import numpy as np


def softmax(z):
    z = z - z.max(1, keepdims=True)
    e = np.exp(z)
    return e / e.sum(1, keepdims=True)


class Dense:
    """Fully connected layer with an activation (relu / tanh / linear)."""

    def __init__(self, n_in, n_out, act, rng):
        scale = np.sqrt(2.0 / n_in) if act == "relu" else np.sqrt(1.0 / n_in)  # He / Xavier init
        self.W = rng.normal(0.0, scale, (n_in, n_out))
        self.b = np.zeros(n_out)
        self.act = act

    def forward(self, x):
        self.x = x
        self.z = x @ self.W + self.b
        if self.act == "relu":
            return np.maximum(self.z, 0.0)
        if self.act == "tanh":
            return np.tanh(self.z)
        return self.z

    def backward(self, g):
        if self.act == "relu":
            g = g * (self.z > 0)
        elif self.act == "tanh":
            g = g * (1.0 - np.tanh(self.z) ** 2)
        self.dW = self.x.T @ g
        self.db = g.sum(0)
        return g @ self.W.T


class MLP:
    """Multi-layer perceptron. loss='mse' (autoencoder) or 'ce' (softmax classifier)."""

    def __init__(self, sizes, acts, loss="mse", seed=0):
        rng = np.random.default_rng(seed)
        self.layers = [Dense(a, b, f, rng) for a, b, f in zip(sizes[:-1], sizes[1:], acts)]
        self.sizes, self.acts, self.loss, self.seed = list(sizes), list(acts), loss, seed
        self._m, self._v, self._t = {}, {}, 0

    def forward(self, x):
        for layer in self.layers:
            x = layer.forward(x)
        return x

    def proba(self, x):
        return softmax(self.forward(x))

    def loss_and_grad(self, x, y, w=None):
        """Returns the loss and fills every layer's dW / db (manual backpropagation)."""
        out = self.forward(x)
        n = len(x)
        if self.loss == "mse":
            d = out - y
            L = float(np.mean(d ** 2))
            g = 2.0 * d / d.size
        else:
            p = softmax(out)
            sw = np.ones(n) if w is None else w[y]
            L = float(-np.sum(sw * np.log(p[np.arange(n), y] + 1e-12)) / n)
            g = p.copy()
            g[np.arange(n), y] -= 1.0
            g *= (sw / n)[:, None]
        for layer in reversed(self.layers):
            g = layer.backward(g)
        return L

    def _adam(self, lr, wd, b1=0.9, b2=0.999, eps=1e-8):
        self._t += 1
        for i, layer in enumerate(self.layers):
            for name in ("W", "b"):
                g = getattr(layer, "d" + name)
                if name == "W" and wd:
                    g = g + wd * layer.W
                key = (i, name)
                m = self._m.get(key, 0.0) * b1 + (1 - b1) * g
                v = self._v.get(key, 0.0) * b2 + (1 - b2) * g * g
                self._m[key], self._v[key] = m, v
                step = lr * (m / (1 - b1 ** self._t)) / (np.sqrt(v / (1 - b2 ** self._t)) + eps)
                setattr(layer, name, getattr(layer, name) - step)

    def fit(self, X, Y, epochs=30, batch=256, lr=3e-3, wd=1e-5, class_w=None, X_val=None, Y_val=None, seed=0):
        rng = np.random.default_rng(seed)
        hist = {"train": [], "val": []}
        n = len(X)
        for ep in range(epochs):
            idx = rng.permutation(n)
            tot = 0.0
            lr_ep = lr * (0.9 * 0.5 * (1 + np.cos(np.pi * ep / epochs)) + 0.1)  # cosine LR decay
            for s in range(0, n, batch):
                b = idx[s:s + batch]
                tot += self.loss_and_grad(X[b], Y[b], class_w) * len(b)
                self._adam(lr_ep, wd)
            hist["train"].append(tot / n)
            if X_val is not None:
                hist["val"].append(self.loss_and_grad(X_val, Y_val, class_w))
        return hist

    def get_params(self):
        return [a for l in self.layers for a in (l.W, l.b)]

    def set_params(self, arrs):
        for i, l in enumerate(self.layers):
            l.W, l.b = arrs[2 * i].copy(), arrs[2 * i + 1].copy()

    def n_params(self):
        return int(sum(a.size for a in self.get_params()))
