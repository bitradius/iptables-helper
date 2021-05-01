// Copyright (c) 2019-2021, BitRadius Holdings, LLC
//
// Please see the included LICENSE file for more information.

import { EventEmitter } from 'events';
import Cache from '@bitradius/memcache-helper';
import * as which from 'which';
import { exec } from 'child_process';
import { format } from 'util';

export default class extends EventEmitter {
    private readonly m_cache: Cache;
    private readonly m_iptables: string;

    constructor (private m_chain: string, ttl = 300) {
        super();

        this.m_cache = new Cache(ttl, Math.ceil(ttl * 0.1));

        this.m_cache.on('error', error => this.emit('error', error));
        this.m_cache.on('expired', async (key) => await this.del(key));

        this.m_iptables = which.sync('iptables', { nothrow: true }) || '/usr/sbin/iptables';
    }

    public on(event: 'error', listener: (error: Error) => void): this;

    public on(event: 'expired', listener: (key: any) => void): this;

    public on (event: any, listener: (...args: any[]) => void): this {
        return super.on(event, listener);
    }

    private async _add (ip: string, nothrow = false): Promise<void> {
        return new Promise((resolve, reject) => {
            const cmd = format('%s -A %s -s %s -j ACCEPT', this.m_iptables, this.m_chain, ip);

            exec(cmd, (error) => {
                if (error && !nothrow) {
                    return reject(error);
                }

                return resolve();
            });
        });
    }

    public async add (ip: string): Promise<boolean> {
        if (!await this.m_cache.exists(ip)) {
            await this._add(ip);

            await this.m_cache.set(ip, true);

            return true;
        } else {
            await this.m_cache.set(ip, true);

            return false;
        }
    }

    public async addInterface (iface: string, nothrow = false): Promise<void> {
        return new Promise((resolve, reject) => {
            const cmd = format('%s -A %s -i %s -j ACCEPT', this.m_iptables, this.m_chain, iface);

            exec(cmd, (error) => {
                if (error && !nothrow) {
                    return reject(error);
                }

                return resolve();
            });
        });
    }

    public async del (ip: string): Promise<boolean> {
        if (!await this.m_cache.exists(ip)) {
            return false;
        }

        await this.m_cache.del(ip);

        try {
            await this.flush();
        } catch {
            return false;
        }

        const list = await this.list();

        const p = [];

        for (const [key] of list) {
            p.push(this._add(key));
        }

        await Promise.all(p);

        return true;
    }

    public async flush (nothrow = false): Promise<void> {
        return new Promise((resolve, reject) => {
            const cmd = format('%s -F %s', this.m_iptables, this.m_chain);

            exec(cmd, (error) => {
                if (error && !nothrow) {
                    return reject(error);
                }

                return resolve();
            });
        });
    }

    public async flushAll (): Promise<void> {
        await this.flush();

        await this.m_cache.flush();
    }

    public async keepAlive (ip: string): Promise<boolean> {
        return this.add(ip);
    }

    public async list (): Promise<Map<string, any>> {
        return this.m_cache.list();
    }
}
