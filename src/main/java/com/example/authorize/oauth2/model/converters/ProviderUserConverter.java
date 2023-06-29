package com.example.authorize.oauth2.model.converters;

public interface ProviderUserConverter<T, R> {
    R convert(T t);
}
