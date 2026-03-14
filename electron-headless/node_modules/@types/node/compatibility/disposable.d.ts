// Polyfills for the explicit resource management types added in TypeScript 5.2.

interface SymbolConstructor {
    readonly dispose: unique symbol;
    readonly asyncDispose: unique symbol;
}

interface Disposable {
    [Symbol.dispose](): void;
}

interface AsyncDisposable {
    [Symbol.asyncDispose](): PromiseLike<void>;
}
