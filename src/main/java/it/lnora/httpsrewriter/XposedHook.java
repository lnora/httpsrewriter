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
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

import de.robv.android.xposed.IXposedHookZygoteInit;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;
import de.robv.android.xposed.XSharedPreferences;

import static de.robv.android.xposed.XposedHelpers.callMethod;

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

		final Class<?> proxy = findClass("android.net.Proxy", lpparam.classLoader);
		XposedBridge.hookAllMethods(proxy, "getProxy", new XC_MethodHook() {
			@Override
			protected void afterHookedMethod(MethodHookParam param) throws Throwable {				
				String url = (String)param.args[1];
				if (verbose) {
					XposedBridge.log(String.format("getProxy(%s)", url));
				}
			}
		});		
		
		final Class<?> proxyProperties = findClass("android.net.ProxyProperties", lpparam.classLoader);
		XposedBridge.hookAllMethods(proxyProperties, "isExcluded", new XC_MethodHook() {
			@Override
			protected void afterHookedMethod(MethodHookParam param) throws Throwable {
				Boolean res = (Boolean)param.getResult();
				
				if (res) {
					return;
				}
								
				String url = (String)param.args[0];
				if (verbose) {
					XposedBridge.log(String.format("isExcluded(%s)", url));
				}
			}
		});

		final Class<?> url = findClass("java.net.URL", lpparam.classLoader);
		XposedBridge.hookAllMethods(url, "openConnection", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {							
				URL url = (URL)param.thisObject;
				if (verbose) {
					XposedBridge.log(String.format("openConnection(%s)", url.toString()));
				}
				
				if (param.args.length != 1 || param.args[0].getClass() != Proxy.class) {
					return;
				}				
				
				if (directHttps && url.getProtocol().equals("https")) {
					param.args[0] = Proxy.NO_PROXY;
					if (verbose) {
						XposedBridge.log(String.format("%s NO_PROXY", url.toString()));
					}
				}
			}
		});
		
		final Class<?> proxySelector = findClass("java.net.ProxySelectorImpl", lpparam.classLoader);
		XposedBridge.hookAllMethods(proxySelector, "select", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
				if (directHttps) {
					URI uri = (URI)param.args[0];
					if (verbose) {
						XposedBridge.log(String.format("select(%s)", uri.toString()));
					}
					
					if (uri.getScheme().equalsIgnoreCase("https")) {
						List<Proxy> proxyList = Collections.singletonList(Proxy.NO_PROXY);					
						param.setResult(proxyList);
						if (verbose) {
							XposedBridge.log(String.format("%s NO_PROXY", uri.toString()));
						}
					}
				}
			}
		});
		
		try {
			final Class<?> httpsHandler = findClass("com.android.okhttp.HttpsHandler", lpparam.classLoader);
			XposedBridge.hookAllMethods(httpsHandler, "newOkUrlFactory", new XC_MethodHook() {
				@Override
				protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
					if (directHttps) {
						param.args[0] = Proxy.NO_PROXY;
						if (verbose) {
							XposedBridge.log("newOkUrlFactory()");
						}
					}				
				}
			});
		} catch (XposedHelpers.ClassNotFoundError e) {
        } catch (NoSuchMethodError e){
        }			

		try {
			final Class<?> urlRequestContext = findClass("org.chromium.net.UrlRequestContext", lpparam.classLoader);
			XposedBridge.hookAllMethods(urlRequestContext, "createRequest", new XC_MethodHook() {
				@Override
				protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
					String url = (String)param.args[0];
					try {
						URI newUrl = rewriteHttpsUriToHttpUri(new URI(url), "createRequest");
						if (newUrl != null) {
							param.args[0] = (String)newUrl.toURL().toString();						
						}
					} catch (IllegalArgumentException e) {
					} catch (MalformedURLException e) {					
					} catch (URISyntaxException e) {}					

					if (verbose) {
						XposedBridge.log(String.format("createRequest(%s)", (String)param.args[0]));
					}				
				}
			});
        } catch (XposedHelpers.ClassNotFoundError e) {
        } catch (NoSuchMethodError e){
        }			

		try {
			final Class<?> cronetUrlRequest = findClass("org.chromium.net.CronetUrlRequest", lpparam.classLoader);
			XposedBridge.hookAllConstructors(cronetUrlRequest, new XC_MethodHook() {
				@Override
				protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
					String url = (String)param.args[2];
					try {
						URI newUrl = rewriteHttpsUriToHttpUri(new URI(url), "CronetUrlRequest");
						if (newUrl != null) {
							param.args[2] = (String)newUrl.toURL().toString();						
						}
					} catch (IllegalArgumentException e) {
					} catch (MalformedURLException e) {					
					} catch (URISyntaxException e) {}					

					if (verbose) {
						XposedBridge.log(String.format("CronetUrlRequest(%s)", (String)param.args[2]));
					}				
				}
			});
        } catch (XposedHelpers.ClassNotFoundError e) {
        } catch (NoSuchMethodError e){
        }

		/*try {
			final Class<?> urlRequestContextConfig = findClass("org.chromium.net.UrlRequestContextConfig", lpparam.classLoader);
			XposedBridge.hookAllConstructors(urlRequestContextConfig, new XC_MethodHook() {
				@Override
				protected void afterHookedMethod(MethodHookParam param) throws Throwable {
					Object config = param.thisObject;
					
					if 
					
					try {
						URI newUrl = rewriteHttpsUriToHttpUri(new URI(url), "CronetUrlRequest");
						if (newUrl != null) {
							param.args[2] = (String)newUrl.toURL().toString();						
						}
					} catch (IllegalArgumentException e) {
					} catch (MalformedURLException e) {					
					} catch (URISyntaxException e) {}					

					if (verbose) {
						XposedBridge.log(String.format("CronetUrlRequest(%s)", (String)param.args[2]));
					}				
				}
			});
        } catch (XposedHelpers.ClassNotFoundError e) {
        } catch (NoSuchMethodError e){
        }*/		
		
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
					if (verbose) {
						XposedBridge.log(String.format("com.squareup.okhttp.OkHttpClient.open %d", param.args.length));
					}
                    URI newUri = rewriteHttpsUriToHttpUri((URI) param.args[0], "OkHttpClient open");
                    if (newUri != null)  {
                        param.args[0] = newUri;
                    }
					if (param.args.length > 1) {
						param.args[1] = Proxy.NO_PROXY;
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
