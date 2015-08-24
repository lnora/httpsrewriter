package it.lnora.httpsrewriter;

import static de.robv.android.xposed.XposedHelpers.findAndHookMethod;
import static de.robv.android.xposed.XposedHelpers.findClass;

import android.app.Activity;
import android.app.Application;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.app.Application;
import android.os.Handler;
import android.os.Looper;
import de.robv.android.xposed.*;

import java.net.*;
import java.util.ArrayList;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

import de.robv.android.xposed.IXposedHookZygoteInit;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;
import de.robv.android.xposed.XSharedPreferences;

import org.apache.http.HttpHost;

public class XposedHook implements IXposedHookZygoteInit, IXposedHookLoadPackage {
	private static XSharedPreferences pref;
	public static final String MY_PACKAGE_NAME = XposedHook.class.getPackage().getName();
	String expr = "";
	Boolean verbose = false;
	Boolean directHttps = false;

	@Override
	public void initZygote(StartupParam startupParam) {
		pref = new XSharedPreferences(MY_PACKAGE_NAME);
	}		
	
    @Override
    public void handleLoadPackage(LoadPackageParam lpparam) throws Throwable {
		pref.reload();
		
		verbose = pref.getBoolean("verbose", false);
		directHttps = pref.getBoolean("set_https_proxy", false);
		
		if (!pref.getBoolean("is_on", true)) {
			return;
		}
				
		String tmpList = pref.getString("whitelist_pkg", null);
		
		if (tmpList != null && tmpList.contains(lpparam.packageName)) {
			XposedBridge.log(String.format("%s in whitelist", lpparam.packageName));
			return;
		}
		
		expr = pref.getString("expr", ".*\\.(?:jpg|gif|png|mp4)$");	

		try {
			final Class<?> httpsConnection = findClass("android.net.http.HttpsConnection", lpparam.classLoader);
			XposedBridge.hookAllConstructors(httpsConnection, new XC_MethodHook() {
				@Override
				protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
					if (param.args.length < 4) {
						return;
					}

					HttpHost proxy = (HttpHost)param.args[2];
					if (proxy != null && directHttps) {
						param.args[2] = null;
					}
				}
			});
        } catch (XposedHelpers.ClassNotFoundError e) {
        } catch (NoSuchMethodError e){
        }

        final Class<?> httpUrlConnection = findClass("java.net.HttpURLConnection", lpparam.classLoader);
        XposedBridge.hookAllConstructors(httpUrlConnection, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                if (param.args.length != 1 || param.args[0].getClass() != URL.class) {
                    return;
                }

				URL url = (URL)param.args[0];
				try {
					URI newUrl = rewriteHttpsUriToHttpUri(new URI(url.toString()), "HttpURLConnection");
					if (newUrl != null) {
						param.args[0] = (URL)newUrl.toURL();						
					}
				} catch (IllegalArgumentException e) {
				} catch (MalformedURLException e) {					
				} catch (URISyntaxException e) {}
            }
        });

        final Class<?> httpRequestBase = findClass("org.apache.http.client.methods.HttpRequestBase", lpparam.classLoader);
        findAndHookMethod(httpRequestBase, "setURI", URI.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                URI newUri = rewriteHttpsUriToHttpUri((URI) param.args[0], "OkHttpClient open");
                if (newUri != null)  {
                    param.args[0] = newUri;
                }
            }
        });

        // NB: Unlike the above hooks, not every app will have OkHttp 1.x available
        try {
            final Class<?> okHttpClient = findClass("com.squareup.okhttp.OkHttpClient", lpparam.classLoader);

            findAndHookMethod(okHttpClient, "open", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    URI newUri = rewriteHttpsUriToHttpUri((URI) param.args[0], "OkHttpClient open");
                    if (newUri != null)  {
                        param.args[0] = newUri;
                    }
					if (directHttps && param.args.length > 1) {
						param.args[1] = null;
						if (verbose) {
							XposedBridge.log(String.format("%s NO_PROXY", newUri.toString()));
						}						
					}					
                }
            });
        } catch (XposedHelpers.ClassNotFoundError e) {
        } catch (NoSuchMethodError e){
        }

	// NB: Same deal, but for OkHttp 2.x's async API
        try {
            final Class<?> okHttpClient = findClass("com.squareup.okhttp.Request.Builder", lpparam.classLoader);

            findAndHookMethod(okHttpClient, "url", String.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
					URI oldUri = new URI((String)param.args[0]);
                    URI newUri = rewriteHttpsUriToHttpUri(oldUri, "OkHttp 2.0 Async");
                    if (newUri != null)  {
                        param.args[0] = newUri.toString();
                    }
                }
            });
        } catch (XposedHelpers.ClassNotFoundError e) {
        } catch (NoSuchMethodError e){
        }

        // https://code.google.com/p/httpclientandroidlib, used in Instagram
        try {
            final Class<?> boyeHttpRequestBase = findClass("ch.boye.httpclientandroidlib.client.methods.HttpRequestBase", lpparam.classLoader);
            findAndHookMethod(boyeHttpRequestBase, "setURI", URI.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    URI newUri = rewriteHttpsUriToHttpUri((URI) param.args[0], "boye.ch HttpClient");
                    if (newUri != null)  {
                        param.args[0] = newUri;
                    }
                }
            });
        } catch (XposedHelpers.ClassNotFoundError e) {
        } catch (NoSuchMethodError e){
        }
    }
      
    private URI rewriteHttpsUriToHttpUri(URI sourceUrl, String methodHint) throws URISyntaxException {
        String scheme = sourceUrl.getScheme();
		String newUrl = "";
		
		//FIXME
		if (scheme.contains("https")) {
			String path = sourceUrl.getPath();
			Pattern pattern = Pattern.compile(this.expr);
			Matcher matcher = pattern.matcher(path);
			if (matcher.find()) {
				newUrl = sourceUrl.toString().replace("https://", "http://");
			} else {
				return null;
			}
		} else {
			return null;
		}

		if (verbose) {
			XposedBridge.log(String.format("About to rewrite '%s' => '%s (%s)'", sourceUrl.toString(), newUrl, methodHint));	
		}
        return new URI(newUrl);
    }
}
